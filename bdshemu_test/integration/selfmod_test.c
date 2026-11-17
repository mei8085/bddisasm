/*
 * Copyright (c) 2026 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration tests for self-modifying code semantics in the controlled x86 emulator.
 *
 * The tests drive the public bdshemu emulation API (ShemuEmulate) directly. Samples are raw
 * instruction bytes supplied by this file and are copied into an emulation buffer allocated by
 * the test itself; the emulator never touches process memory and no external process is started.
 *
 * The verdict does NOT depend on the disassembly text format. Nothing in this file calls
 * NdToText or looks at a rendered instruction string. The tests assert on:
 *   - the raw instruction bytes (and their length) fetched at every executed address;
 *   - the executed address trajectory (the reverse trace);
 *   - architectural state (registers, emulation flags, counters) and abort statuses;
 *   - the contents of the emulation buffer, including guard bytes past the shellcode end.
 *
 * Semantics covered:
 *
 *  1. Instruction writes are observed by later fetches. After a store into the emulated
 *     shellcode, the next fetch at that address is decoded from the updated bytes:
 *       - test_rewrite_immediate            - a MOV immediate is replaced;
 *       - test_rewrite_across_boundary      - one store covers the tail of an instruction and
 *                                             the opcode of the next one, changing which path
 *                                             the branch takes;
 *       - test_overlapping_instruction      - a branch jumps into its own displacement byte and
 *                                             the instruction decoded there changes meaning;
 *       - test_rewrite_changes_length       - a 5-byte instruction shrinks to 2 bytes, shifting
 *                                             every following execution address;
 *       - test_rewrite_immediate_32bit      - the same guarantee in 32-bit mode.
 *
 *  2. Out-of-bounds stores are distinguished from legal self-modification. A store that starts
 *     inside the shellcode but ends past its end aborts with SHEMU_ABORT_GLA_OUTSIDE. The stop
 *     reason, the executed-byte trajectory, the writes that were legally committed before the
 *     abort, and the RIP of the failing instruction all remain inspectable; no partially
 *     written bytes may appear and no bytes may be written outside the shellcode.
 *
 *  3. SHEMU_OPT_BYPASS_SELF_WRITES is the explicit opt-out: in that mode a legal self-write is
 *     discarded, so later fetches keep seeing the original bytes and no abort is raised. This
 *     separates "write applied", "write discarded by policy" and "write rejected as OOB".
 *
 * The samples use only instructions that the emulator supports in the configured mode, and do
 * not rely on external memory access callbacks.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bdshemu.h"


#define SHELL_BASE          0x200000ULL

#define STACK_BASE          0x1FE000ULL
#define STACK_SIZE          0x2000ULL
#define STACK_RSP           (STACK_BASE + STACK_SIZE - 0x100ULL)

/* Bytes placed after the end of the shellcode; used to prove that no out-of-bounds write
 * happened. They are never part of the emulated shellcode. */
#define GUARD_SIZE          0x20U
#define GUARD_BYTE          0xA5U

/* Hard limit on recorded single steps, so a broken emulator cannot hang the test. */
#define MAX_STEPS           128


typedef struct _TEST_STEP
{
    uint64_t    Offset;             // Address of the instruction, relative to ShellcodeBase.
    uint32_t    Length;             // Fetched instruction length.
    uint8_t     Bytes[16];          // Fetched instruction bytes, as decoded.
} TEST_STEP;


typedef struct _TEST_STATE
{
    uint32_t    Status;             // Status of the last emulated instruction / abort reason.
    uint64_t    Rax;
    uint64_t    Rbx;
    uint64_t    Rcx;
    uint64_t    Rdx;
    uint64_t    Rsi;
    uint64_t    Rdi;
    uint64_t    Rip;                // RIP after the last emulated instruction.
    uint64_t    Flags;              // SHEMU_CONTEXT::Flags (shellcode indicators).
    uint64_t    InstructionCount;   // SHEMU_CONTEXT::InstructionsCount.
    uint64_t    UniqueCount;        // SHEMU_CONTEXT::UniqueCount.
} TEST_STATE;


typedef struct _TEST_RUN
{
    TEST_STEP   Steps[MAX_STEPS];
    uint32_t    StepCount;
    TEST_STATE  State;

    uint8_t     Buffer[MAX_STEPS * 16 + GUARD_SIZE]; // Final shellcode + guard bytes.
    uint32_t    BufferSize;

    int         GuardIntact;
    int         Truncated;          // Set if MAX_STEPS was reached before emulation stopped.
} TEST_RUN;


typedef struct _EXPECTED_STEP
{
    uint64_t        Offset;
    const char      *Hex;           // Fetched instruction bytes, uppercase hex.
} EXPECTED_STEP;


static int g_Failures = 0;
static int g_Checks = 0;


static int
hex_value(
    char c
    )
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    return -1;
}


static void
bytes_to_hex(
    const uint8_t *Bytes,
    uint32_t Length,
    char *Hex,
    size_t HexSize
    )
{
    static const char digits[] = "0123456789ABCDEF";

    if (HexSize < (size_t)Length * 2 + 1)
    {
        Length = (uint32_t)((HexSize - 1) / 2);
    }

    for (uint32_t i = 0; i < Length; i++)
    {
        Hex[i * 2 + 0] = digits[(Bytes[i] >> 4) & 0xF];
        Hex[i * 2 + 1] = digits[Bytes[i] & 0xF];
    }

    Hex[Length * 2] = 0;
}


static int
hex_matches(
    const uint8_t *Bytes,
    uint32_t Length,
    const char *Hex
    )
{
    size_t hexLen = strlen(Hex);

    if (hexLen != (size_t)Length * 2)
    {
        return 0;
    }

    for (uint32_t i = 0; i < Length; i++)
    {
        int hi = hex_value(Hex[i * 2 + 0]);
        int lo = hex_value(Hex[i * 2 + 1]);

        if (hi < 0 || lo < 0 || Bytes[i] != (uint8_t)((hi << 4) | lo))
        {
            return 0;
        }
    }

    return 1;
}


#define CHECK(Cond, ...)                                                                \
    do                                                                                  \
    {                                                                                   \
        g_Checks++;                                                                     \
        if (!(Cond))                                                                    \
        {                                                                               \
            g_Failures++;                                                               \
            printf("    FAIL: ");                                                       \
            printf(__VA_ARGS__);                                                        \
            printf("  (%s:%d)\n", __FILE__, __LINE__);                                  \
        }                                                                               \
    } while (0)


/*
 * Set up a fresh emulation context over the test-provided code and run it.
 *
 * When SingleStep is non-zero, one instruction is emulated per ShemuEmulate call, which lets
 * the test record the exact bytes fetched at each executed address. When it is zero, a single
 * call runs the whole sample, which is used to observe the natural abort status and counters.
 */
static void
execute(
    TEST_RUN *Run,
    const uint8_t *Code,
    uint32_t CodeSize,
    uint32_t ShellSize,
    uint8_t Mode,
    uint64_t Options,
    int SingleStep
    )
{
    SHEMU_CONTEXT ctx;
    uint8_t *shellcode;
    uint8_t *stack;
    uint8_t *intbuf;
    uint32_t status = SHEMU_SUCCESS;

    memset(Run, 0, sizeof(*Run));

    if (ShellSize > MAX_STEPS * 16 || CodeSize > ShellSize)
    {
        printf("    FAIL: sample does not fit the test harness\n");
        g_Failures++;
        return;
    }

    shellcode = (uint8_t *)malloc((size_t)ShellSize + GUARD_SIZE);
    stack = (uint8_t *)calloc(1, STACK_SIZE);
    intbuf = (uint8_t *)calloc(1, (size_t)ShellSize + STACK_SIZE);
    if (shellcode == NULL || stack == NULL || intbuf == NULL)
    {
        printf("    FAIL: out of memory\n");
        g_Failures++;
        free(shellcode);
        free(stack);
        free(intbuf);
        return;
    }

    memset(shellcode, 0, (size_t)ShellSize + GUARD_SIZE);
    memcpy(shellcode, Code, CodeSize);
    memset(shellcode + ShellSize, GUARD_BYTE, GUARD_SIZE);

    memset(&ctx, 0, sizeof(ctx));
    ctx.ArchType = SHEMU_ARCH_TYPE_X86;
    ctx.Shellcode = shellcode;
    ctx.ShellcodeBase = SHELL_BASE;
    ctx.ShellcodeSize = ShellSize;
    ctx.Stack = stack;
    ctx.StackBase = STACK_BASE;
    ctx.StackSize = STACK_SIZE;
    ctx.Intbuf = intbuf;
    ctx.IntbufSize = (uint64_t)ShellSize + STACK_SIZE;
    ctx.Arch.X86.Mode = Mode;
    ctx.Arch.X86.Ring = 3;
    ctx.Arch.X86.Registers.RegRsp = STACK_RSP;
    ctx.Arch.X86.Registers.RegFlags = NDR_RFLAG_IF | 2;
    ctx.Arch.X86.Registers.RegRip = SHELL_BASE;
    ctx.Arch.X86.Segments.Cs.Selector = 0x33;
    ctx.Arch.X86.Segments.Ds.Selector = 0x2b;
    ctx.Arch.X86.Segments.Es.Selector = 0x2b;
    ctx.Arch.X86.Segments.Ss.Selector = 0x2b;
    ctx.TibBase = 0x7FFF0000;
    ctx.Options = Options;
    ctx.MaxInstructionsCount = MAX_STEPS;

    if (SingleStep)
    {
        for (;;)
        {
            uint64_t rip = ctx.Arch.X86.Registers.RegRip;
            TEST_STEP *step;

            if (rip < SHELL_BASE || rip >= SHELL_BASE + ShellSize)
            {
                // Execution left the shellcode (for example, after RET). Nothing to fetch.
                break;
            }

            if (Run->StepCount >= MAX_STEPS)
            {
                Run->Truncated = 1;
                status = SHEMU_SUCCESS;
                break;
            }

            // One instruction per call. The emulator runs exactly one instruction and returns.
            ctx.MaxInstructionsCount = ctx.InstructionsCount + 1;

            status = ShemuEmulate(&ctx);

            step = &Run->Steps[Run->StepCount++];
            step->Offset = rip - SHELL_BASE;
            step->Length = ctx.Arch.X86.Instruction.Length;
            if (step->Length > sizeof(step->Bytes))
            {
                step->Length = sizeof(step->Bytes);
            }
            memcpy(step->Bytes, ctx.Arch.X86.Instruction.InstructionBytes, step->Length);

            if (status != SHEMU_SUCCESS)
            {
                break;
            }
        }
    }
    else
    {
        status = ShemuEmulate(&ctx);
    }

    Run->State.Status = status;
    Run->State.Rax = ctx.Arch.X86.Registers.RegRax;
    Run->State.Rbx = ctx.Arch.X86.Registers.RegRbx;
    Run->State.Rcx = ctx.Arch.X86.Registers.RegRcx;
    Run->State.Rdx = ctx.Arch.X86.Registers.RegRdx;
    Run->State.Rsi = ctx.Arch.X86.Registers.RegRsi;
    Run->State.Rdi = ctx.Arch.X86.Registers.RegRdi;
    Run->State.Rip = ctx.Arch.X86.Registers.RegRip;
    Run->State.Flags = ctx.Flags;
    Run->State.InstructionCount = ctx.InstructionsCount;
    Run->State.UniqueCount = ctx.UniqueCount;

    memcpy(Run->Buffer, shellcode, (size_t)ShellSize + GUARD_SIZE);
    Run->BufferSize = (size_t)ShellSize + GUARD_SIZE;

    Run->GuardIntact = 1;
    for (uint32_t i = 0; i < GUARD_SIZE; i++)
    {
        if (shellcode[ShellSize + i] != GUARD_BYTE)
        {
            Run->GuardIntact = 0;
            break;
        }
    }

    free(shellcode);
    free(stack);
    free(intbuf);
}


static void
dump_run(
    const TEST_RUN *Run
    )
{
    char hex[2 * 16 + 1];

    printf("    steps=%u status=0x%x rip=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rsi=0x%llx flags=0x%llx\n",
           Run->StepCount, Run->State.Status,
           (unsigned long long)Run->State.Rip, (unsigned long long)Run->State.Rax,
           (unsigned long long)Run->State.Rbx, (unsigned long long)Run->State.Rcx,
           (unsigned long long)Run->State.Rsi, (unsigned long long)Run->State.Flags);

    for (uint32_t i = 0; i < Run->StepCount; i++)
    {
        bytes_to_hex(Run->Steps[i].Bytes, Run->Steps[i].Length, hex, sizeof(hex));
        printf("      @%02llx len=%u bytes=%s\n", (unsigned long long)Run->Steps[i].Offset,
               Run->Steps[i].Length, hex);
    }
}


static void
check_trace(
    const TEST_RUN *Run,
    const EXPECTED_STEP *Expected,
    uint32_t ExpectedCount
    )
{
    if (Run->Truncated)
    {
        CHECK(0, "emulation did not stop within %u steps", MAX_STEPS);
        return;
    }

    if (Run->StepCount != ExpectedCount)
    {
        CHECK(0, "executed %u instructions, expected %u", Run->StepCount, ExpectedCount);
        dump_run(Run);
        return;
    }

    for (uint32_t i = 0; i < ExpectedCount; i++)
    {
        const TEST_STEP *step = &Run->Steps[i];
        char actual[2 * 16 + 1];

        bytes_to_hex(step->Bytes, step->Length, actual, sizeof(actual));

        if (step->Offset != Expected[i].Offset || !hex_matches(step->Bytes, step->Length, Expected[i].Hex))
        {
            CHECK(0, "step %u: fetched %s at @%02llx, expected %s at @%02llx", i, actual,
                  (unsigned long long)step->Offset, Expected[i].Hex,
                  (unsigned long long)Expected[i].Offset);
            dump_run(Run);
            return;
        }
    }

    g_Checks++;
}


static uint32_t
buffer_dword(
    const TEST_RUN *Run,
    uint32_t Offset
    )
{
    return (uint32_t)Run->Buffer[Offset] |
           ((uint32_t)Run->Buffer[Offset + 1] << 8) |
           ((uint32_t)Run->Buffer[Offset + 2] << 16) |
           ((uint32_t)Run->Buffer[Offset + 3] << 24);
}


/*
 * Test 1: a MOV immediate store is observed by the next fetch of the same instruction.
 *
 * The loop executes "mov eax, 0x11111111" once, rewrites its immediate to 0x11223344 and
 * jumps back. The second execution of the same address must decode and execute the new bytes.
 */
static void
test_rewrite_immediate(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0xEB, 0x05,                                           // 05: jmp 0x0C
        0x90, 0x90, 0x90, 0x90, 0x90,                         // 07: nop x5
        0xB8, 0x11, 0x11, 0x11, 0x11,                         // 0C: mov eax, 0x11111111
        0x48, 0x8D, 0x35, 0xF5, 0xFF, 0xFF, 0xFF,             // 11: lea rsi, [0x0D]
        0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                   // 18: mov dword [rsi], 0x11223344
        0xFE, 0xC9,                                           // 1E: dec cl
        0x75, 0xEA,                                           // 20: jnz 0x0C
        0xC3                                                  // 22: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "EB05" },
        { 0x0C, "B811111111" },     // Original immediate.
        { 0x11, "488D35F5FFFFFF" },
        { 0x18, "C70644332211" },
        { 0x1E, "FEC9" },
        { 0x20, "75EA" },
        { 0x0C, "B844332211" },     // Re-fetched: the store is visible.
        { 0x11, "488D35F5FFFFFF" },
        { 0x18, "C70644332211" },
        { 0x1E, "FEC9" },
        { 0x20, "75EA" },
        { 0x22, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_rewrite_immediate\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_64, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0x11223344ULL, "expected eax=0x11223344, got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK(run.State.Rcx == 0, "expected ecx=0, got 0x%llx", (unsigned long long)run.State.Rcx);
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) != 0, "SHEMU_FLAG_WRITE_SELF not set");
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
    // The overwritten immediate (bytes at 0x0D..0x10) must hold the stored value.
    CHECK(buffer_dword(&run, 0x0D) == 0x11223344U, "stored bytes not present in the buffer");
}


/*
 * Test 2: a store that straddles an instruction boundary changes the instruction that follows.
 *
 * The write covers the last immediate byte of "mov eax, imm32" and the opcode byte of the
 * following "jnz". The second iteration must fetch the last immediate byte as 0x22 and decode
 * the branch as "jz" (0x74), so the taken path changes and "mov ebx, imm32" is skipped.
 */
static void
test_rewrite_across_boundary(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0x31, 0xF6,                                           // 05: xor esi, esi (ZF=1)
        0xEB, 0x0D,                                           // 07: jmp 0x16
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,             // 09: nop x7
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,                   // 10: nop x6
        0xB8, 0x11, 0x11, 0x11, 0x11,                         // 16: mov eax, 0x11111111
        0x75, 0x05,                                           // 1B: jnz 0x22
        0xBB, 0x77, 0x77, 0x77, 0x77,                         // 1D: mov ebx, 0x77777777
        0x48, 0x8D, 0x35, 0xF1, 0xFF, 0xFF, 0xFF,             // 22: lea rsi, [0x1A]
        0x66, 0xC7, 0x06, 0x22, 0x74,                         // 29: mov word [rsi], 0x7422
        0xFE, 0xC9,                                           // 2E: dec cl
        0x75, 0xD3,                                           // 30: jnz 0x05
        0xC3                                                  // 32: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "31F6" },
        { 0x07, "EB0D" },
        { 0x16, "B811111111" },
        { 0x1B, "7505" },           // Original jnz, not taken (ZF=1).
        { 0x1D, "BB77777777" },
        { 0x22, "488D35F1FFFFFF" },
        { 0x29, "66C7062274" },
        { 0x2E, "FEC9" },
        { 0x30, "75D3" },
        { 0x05, "31F6" },
        { 0x07, "EB0D" },
        { 0x16, "B811111122" },     // Straddling write changed the immediate's top byte.
        { 0x1B, "7405" },           // Re-decoded as jz, now taken: 0x1D is skipped.
        { 0x22, "488D35F1FFFFFF" },
        { 0x29, "66C7062274" },
        { 0x2E, "FEC9" },
        { 0x30, "75D3" },
        { 0x32, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_rewrite_across_boundary\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_64, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0x22111111ULL, "expected eax=0x22111111, got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK(run.State.Rbx == 0x77777777ULL,
          "expected ebx=0x77777777 (only reachable on the unmodified path), got 0x%llx",
          (unsigned long long)run.State.Rbx);
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) != 0, "SHEMU_FLAG_WRITE_SELF not set");
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
}


/*
 * Test 3: overlapping instructions. The branch at 0x05 has displacement 0xFF, so it lands on its
 * own displacement byte at 0x06. That byte is the ModRM byte of the 2-byte instruction "FF C0"
 * (inc eax) executed at the target. Rewriting it to 0xC8 turns the instruction into "FF C8"
 * (dec eax), and the trace must show both encodings fetched from the same address.
 */
static void
test_overlapping_instruction(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0xEB, 0xFF,                                           // 05: jmp 0x06 (into own disp)
        0xC0,                                                 // 06: FF C0 = inc eax; 07 is the jmp disp
        0x48, 0x8D, 0x35, 0xF8, 0xFF, 0xFF, 0xFF,             // 08: lea rsi, [0x07]
        0xC6, 0x06, 0xC8,                                     // 0F: mov byte [rsi], 0xC8
        0xFE, 0xC9,                                           // 12: dec cl
        0x75, 0xEF,                                           // 14: jnz 0x05
        0xC3                                                  // 16: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "EBFF" },
        { 0x06, "FFC0" },           // inc eax
        { 0x08, "488D35F8FFFFFF" },
        { 0x0F, "C606C8" },
        { 0x12, "FEC9" },
        { 0x14, "75EF" },
        { 0x05, "EBFF" },
        { 0x06, "FFC8" },           // Same address, re-decoded as dec eax.
        { 0x08, "488D35F8FFFFFF" },
        { 0x0F, "C606C8" },
        { 0x12, "FEC9" },
        { 0x14, "75EF" },
        { 0x16, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_overlapping_instruction\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_64, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0, "expected eax=0 (inc then dec), got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK(run.State.Rcx == 0, "expected ecx=0, got 0x%llx", (unsigned long long)run.State.Rcx);
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) != 0, "SHEMU_FLAG_WRITE_SELF not set");
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
    CHECK(run.Buffer[0x07] == 0xC8, "overlapping byte not updated in the buffer");
}


/*
 * Test 4: the rewritten bytes change the instruction length.
 *
 * A 5-byte "mov eax, imm32" is replaced by "xor eax, eax" followed by three NOPs. The second
 * iteration must fetch a 2-byte instruction at 0x15 and then execute the NOPs at 0x17..0x19; the
 * following instruction is still at 0x1A. The reverse trace therefore differs from the first
 * iteration even though the entry address is the same.
 */
static void
test_rewrite_changes_length(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0xEB, 0x0E,                                           // 05: jmp 0x15
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,             // 07: nop x7
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,             // 0E: nop x7
        0xB8, 0x11, 0x11, 0x11, 0x11,                         // 15: mov eax, 0x11111111
        0x48, 0x8D, 0x35, 0xF4, 0xFF, 0xFF, 0xFF,             // 1A: lea rsi, [0x15]
        0xC7, 0x06, 0x31, 0xC0, 0x90, 0x90,                   // 21: mov dword [rsi], 0x9090C031
        0xC6, 0x46, 0x04, 0x90,                               // 27: mov byte [rsi+4], 0x90
        0xFE, 0xC9,                                           // 2B: dec cl
        0x75, 0xE6,                                           // 2D: jnz 0x15
        0xC3                                                  // 2F: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "EB0E" },
        { 0x15, "B811111111" },     // 5-byte mov.
        { 0x1A, "488D35F4FFFFFF" },
        { 0x21, "C70631C09090" },
        { 0x27, "C6460490" },
        { 0x2B, "FEC9" },
        { 0x2D, "75E6" },
        { 0x15, "31C0" },           // Re-fetched as 2-byte xor.
        { 0x17, "90" },             // The three trailing NOPs execute.
        { 0x18, "90" },
        { 0x19, "90" },
        { 0x1A, "488D35F4FFFFFF" },
        { 0x21, "C70631C09090" },
        { 0x27, "C6460490" },
        { 0x2B, "FEC9" },
        { 0x2D, "75E6" },
        { 0x2F, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_rewrite_changes_length\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_64, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0, "expected eax=0 (xor), got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) != 0, "SHEMU_FLAG_WRITE_SELF not set");
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
}


/*
 * Test 5: an out-of-bounds store is reported, not silently turned into a legal self-write.
 *
 * The shellcode is 0x20 bytes, so valid offsets are 0x00..0x1F. The first store writes 2 bytes
 * at 0x1E (fully inside); the second one writes 2 bytes at 0x1F, so its second byte lands at
 * 0x20, just past the end. It must abort with SHEMU_ABORT_GLA_OUTSIDE before any byte is
 * written, while everything executed before the abort stays observable: the legal store is
 * committed in the buffer, the trace of fetched bytes is intact, and RIP reflects the failing
 * instruction (bdshemu increments RIP before emulating, so it points just past it).
 */
static void
test_oob_store_is_distinct(void)
{
    static const uint8_t code[] =
    {
        0x48, 0x8D, 0x35, 0x17, 0x00, 0x00, 0x00,             // 00: lea rsi, [0x1E]
        0x66, 0xC7, 0x06, 0x5A, 0x5A,                         // 07: mov word [rsi], 0x5A5A
        0x48, 0x83, 0xC6, 0x01,                               // 0C: add rsi, 1
        0x66, 0xC7, 0x06, 0x11, 0x22,                         // 10: mov word [rsi], 0x2211 -> crosses end
        0xC3                                                  // 15: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "488D3517000000" },
        { 0x07, "66C7065A5A" },
        { 0x0C, "4883C601" },
        { 0x10, "66C7061122" },     // Fetched, then the store aborts.
    };

    TEST_RUN run, full;

    printf("[*] test_oob_store_is_distinct\n");
    execute(&run, code, sizeof(code), 0x20, ND_CODE_64, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    // Stop reason: the OOB store is reported as such.
    CHECK(run.State.Status == SHEMU_ABORT_GLA_OUTSIDE,
          "expected SHEMU_ABORT_GLA_OUTSIDE, got 0x%x", run.State.Status);

    // Legacy self-write detection is not what stopped the emulation: no fetch happened from a
    // dirty byte, so the shellcode indicator is not set. The two conditions are distinct.
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) == 0,
          "out-of-bounds store must not be reported as a legal self-write");

    // The already executed bytes remain traceable.
    CHECK(run.StepCount == 4, "expected 4 fetched instructions, got %u", run.StepCount);
    CHECK(run.Steps[3].Offset == 0x10, "failing instruction not recorded at 0x10");
    CHECK(hex_matches(run.Steps[3].Bytes, run.Steps[3].Length, "66C7061122"),
          "failing instruction bytes were not retained");

    // RIP was advanced past the failing store.
    CHECK(run.State.Rip == SHELL_BASE + 0x15, "expected RIP=0x%llx, got 0x%llx",
          (unsigned long long)(SHELL_BASE + 0x15), (unsigned long long)run.State.Rip);

    // The legal store before the abort is committed; the failing store wrote nothing at all.
    CHECK(run.Buffer[0x1E] == 0x5A && run.Buffer[0x1F] == 0x5A,
          "legal store at 0x1E not committed");
    CHECK(run.Buffer[0x1F] != 0x11 && run.Buffer[0x1F] != 0x22,
          "partially written out-of-bounds store");
    CHECK(run.GuardIntact, "out-of-bounds store modified bytes outside the shellcode");

    // A full (non single-step) run must report the same stop reason and count exactly the
    // instructions that were fetched before the abort.
    execute(&full, code, sizeof(code), 0x20, ND_CODE_64, 0, 0);
    CHECK(full.State.Status == SHEMU_ABORT_GLA_OUTSIDE,
          "full run: expected SHEMU_ABORT_GLA_OUTSIDE, got 0x%x", full.State.Status);
    CHECK(full.State.InstructionCount == 4, "full run: expected 4 instructions emulated, got %llu",
          (unsigned long long)full.State.InstructionCount);
    CHECK(full.GuardIntact, "full run: out-of-bounds store modified bytes outside the shellcode");
}


/*
 * Test 6: the same write-then-fetch guarantee holds in 32-bit mode, using an absolute address
 * instead of RIP-relative addressing.
 */
static void
test_rewrite_immediate_32bit(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0xEB, 0x05,                                           // 05: jmp 0x0C
        0x90, 0x90, 0x90, 0x90, 0x90,                         // 07: nop x5
        0xB8, 0x11, 0x11, 0x11, 0x11,                         // 0C: mov eax, 0x11111111
        0xBB, 0x0D, 0x00, 0x20, 0x00,                         // 11: mov ebx, 0x20000D
        0xC7, 0x03, 0x44, 0x33, 0x22, 0x11,                   // 16: mov dword [ebx], 0x11223344
        0xFE, 0xC9,                                           // 1C: dec cl
        0x75, 0xEC,                                           // 1E: jnz 0x0C
        0xC3                                                  // 20: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "EB05" },
        { 0x0C, "B811111111" },
        { 0x11, "BB0D002000" },
        { 0x16, "C70344332211" },
        { 0x1C, "FEC9" },
        { 0x1E, "75EC" },
        { 0x0C, "B844332211" },     // Re-fetched from updated bytes in 32-bit mode.
        { 0x11, "BB0D002000" },
        { 0x16, "C70344332211" },
        { 0x1C, "FEC9" },
        { 0x1E, "75EC" },
        { 0x20, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_rewrite_immediate_32bit\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_32, 0, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0x11223344ULL, "expected eax=0x11223344, got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK(run.State.Rbx == 0x20000DULL, "expected ebx=0x20000D, got 0x%llx",
          (unsigned long long)run.State.Rbx);
    CHECK((run.State.Flags & SHEMU_FLAG_WRITE_SELF) != 0, "SHEMU_FLAG_WRITE_SELF not set");
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
}


/*
 * Test 7: SHEMU_OPT_BYPASS_SELF_WRITES must keep the original bytes. This is the opt-out policy;
 * the write is not committed and the second fetch still sees the original instruction. Together
 * with tests 1-6 this separates "legal write that is applied", "legal write discarded by policy"
 * and "out-of-bounds write that aborts".
 */
static void
test_bypass_self_writes_keeps_bytes(void)
{
    static const uint8_t code[] =
    {
        0xB9, 0x02, 0x00, 0x00, 0x00,                         // 00: mov ecx, 2
        0xEB, 0x05,                                           // 05: jmp 0x0C
        0x90, 0x90, 0x90, 0x90, 0x90,                         // 07: nop x5
        0xB8, 0x11, 0x11, 0x11, 0x11,                         // 0C: mov eax, 0x11111111
        0x48, 0x8D, 0x35, 0xF5, 0xFF, 0xFF, 0xFF,             // 11: lea rsi, [0x0D]
        0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                   // 18: mov dword [rsi], 0x11223344
        0xFE, 0xC9,                                           // 1E: dec cl
        0x75, 0xEA,                                           // 20: jnz 0x0C
        0xC3                                                  // 22: ret
    };

    static const EXPECTED_STEP expected[] =
    {
        { 0x00, "B902000000" },
        { 0x05, "EB05" },
        { 0x0C, "B811111111" },
        { 0x11, "488D35F5FFFFFF" },
        { 0x18, "C70644332211" },
        { 0x1E, "FEC9" },
        { 0x20, "75EA" },
        { 0x0C, "B811111111" },     // Unchanged: the write was discarded by policy.
        { 0x11, "488D35F5FFFFFF" },
        { 0x18, "C70644332211" },
        { 0x1E, "FEC9" },
        { 0x20, "75EA" },
        { 0x22, "C3" },
    };

    TEST_RUN run;

    printf("[*] test_bypass_self_writes_keeps_bytes\n");
    execute(&run, code, sizeof(code), sizeof(code), ND_CODE_64, SHEMU_OPT_BYPASS_SELF_WRITES, 1);

    check_trace(&run, expected, sizeof(expected) / sizeof(expected[0]));

    CHECK(run.State.Status == SHEMU_SUCCESS, "expected SHEMU_SUCCESS, got 0x%x", run.State.Status);
    CHECK(run.State.Rax == 0x11111111ULL, "expected eax=0x11111111, got 0x%llx",
          (unsigned long long)run.State.Rax);
    CHECK(run.GuardIntact, "self-modification escaped the shellcode buffer");
    CHECK(buffer_dword(&run, 0x0D) == 0x11111111U,
          "SHEMU_OPT_BYPASS_SELF_WRITES must not modify the shellcode buffer");
}


int
main(void)
{
    printf("bdshemu self-modifying code integration tests\n");

    test_rewrite_immediate();
    test_rewrite_across_boundary();
    test_overlapping_instruction();
    test_rewrite_changes_length();
    test_oob_store_is_distinct();
    test_rewrite_immediate_32bit();
    test_bypass_self_writes_keeps_bytes();

    printf("\n%u checks, %d failure(s)\n", g_Checks, g_Failures);

    return g_Failures == 0 ? 0 : 1;
}
