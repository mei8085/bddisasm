/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration tests for the self-modifying-code (SMC) semantics of bdshemu.
 *
 * The emulator is driven only through its public API (ShemuX86Emulate) and only
 * ever operates on buffers allocated by this test:
 *   - a writable shellcode buffer (the emulated image),
 *   - a virtual stack,
 *   - the internal bitmap buffer.
 * The external-memory callback refuses every access, so no host/process memory
 * is ever read or written by the emulated code. All samples are plain byte
 * arrays, the test does not depend on an assembler or on disassembly text.
 *
 * Two semantic groups are covered:
 *
 * 1. Write-then-fetch coherence.
 *    A store that modifies shellcode bytes must be visible to subsequent
 *    instruction fetches, including stores that land in the middle of an
 *    existing instruction (overlapping / cross-boundary modifications). The
 *    executed instruction stream (addresses and lengths) is reconstructed and
 *    checked against the modified byte stream. A SHEMU_OPT_BYPASS_SELF_WRITES
 *    re-run is used as a control: when the write is discarded, the original
 *    instruction boundaries must remain in effect.
 *
 * 2. Out-of-bounds writes vs. legitimate self-modification.
 *    Stores fully outside, or straddling the end of, the shellcode buffer must
 *    abort with the documented status, must not modify the emulated image and
 *    must leave an unambiguous record of which instructions executed and why
 *    emulation stopped. A same-shape in-bounds store is used to prove that the
 *    abort is caused by the out-of-bounds range, not by the store itself.
 *
 * Trace reconstruction note:
 *    SHEMU_CONTEXT exposes the last decoded instruction and the current RIP
 *    after every run. By re-running the identical image with
 *    MaxInstructionsCount = 1..N (each run starts from a freshly copied image),
 *    run k decodes exactly the k-th executed instruction. Its fetch address is
 *    the RIP left by run k-1 (the initial RIP for the first run), which is
 *    correct even across taken branches; a run that aborts before decoding
 *    anything keeps the previous entry's address and reports the aborted fetch
 *    target through the current RIP. This rebuilds the executed-address trace
 *    without parsing any log text.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"
#include "bdshemu.h"


//
// CRT shims. The CMake build probes libc and compiles these into bddisasm
// (BDD_USE_EXTERNAL_MEMSET / BDD_USE_EXTERNAL_VSNPRINTF); the plain Makefile
// build does not, in which case the integrator is expected to provide them.
// They are weak so a strong definition shipped inside a CMake-built library
// takes precedence and no duplicate-symbol error occurs.
//
#if defined(__GNUC__)
#define BDSHEMU_TEST_WEAK __attribute__((weak))
#else
#define BDSHEMU_TEST_WEAK
#endif

BDSHEMU_TEST_WEAK void *
nd_memset(
    void *s,
    int c,
    ND_SIZET n
    )
{
    return memset(s, c, n);
}

BDSHEMU_TEST_WEAK int
nd_vsnprintf_s(
    char *buffer,
    ND_SIZET sizeOfBuffer,
    ND_SIZET count,
    const char *format,
    va_list argptr
    )
{
    (void)count;
    return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}


#define TEST_SHELL_BASE     0x0000000000200000ull
#define TEST_STACK_BASE     0x0000000000100000ull
#define TEST_STACK_SIZE     0x2000ull
#define TEST_TIB_BASE       0x0000000007fff0000ull


static int gChecks;
static int gFailures;

#define CHECK(cond, ...)                                                                  \
    do                                                                                    \
    {                                                                                     \
        gChecks++;                                                                        \
        if (!(cond))                                                                      \
        {                                                                                 \
            gFailures++;                                                                  \
            printf("    [FAIL] %s:%d: ", __func__, __LINE__);                            \
            printf(__VA_ARGS__);                                                          \
            printf("\n");                                                                \
        }                                                                                 \
    } while (0)


//
// One entry of the reconstructed execution trace.
//
typedef struct _TRACE_STEP
{
    ND_UINT64       Addr;       // Address the instruction was fetched from.
    ND_UINT8        Length;     // Instruction length (stale if fetch failed).
    ND_UINT64       NextRip;    // RIP after the instruction emulated.
    ND_UINT64       Count;      // InstructionsCount at the end of the run.
    SHEMU_STATUS    Status;     // Terminal status of the run.
} TRACE_STEP;


//
// Everything the emulator needs for one isolated run. All three buffers are
// owned by this test and exist solely for emulation; nothing else references
// them.
//
typedef struct _EMU_ENV
{
    SHEMU_CONTEXT   Ctx;
    uint8_t        *Shell;
    uint8_t        *Stack;
    uint8_t        *Intbuf;
    size_t          ShellSize;
} EMU_ENV;


//
// Refuse every access outside the emulated shell/stack. The emulator resolves
// shellcode and stack accesses internally, so this only fires for genuinely
// external addresses - and even then we simply report "unhandled", which makes
// the emulator terminate with SHEMU_ABORT_GLA_OUTSIDE. No host memory is read
// or written.
//
static ND_BOOL
UnhandledExternalAccess(
    void *Context,
    ND_UINT64 Gla,
    ND_SIZET Size,
    ND_UINT8 *Buffer,
    ND_BOOL Store
    )
{
    (void)Context;
    (void)Gla;
    (void)Size;
    (void)Buffer;
    (void)Store;

    return ND_FALSE;
}


static void
EnvDestroy(
    EMU_ENV *Env
    )
{
    free(Env->Shell);
    free(Env->Stack);
    free(Env->Intbuf);
    memset(Env, 0, sizeof(*Env));
}


//
// Initialise a fresh emulation environment from a copy of Code. Every run
// starts from an identical image, so repeated runs with different instruction
// budgets are deterministic.
//
static bool
EnvInit(
    EMU_ENV *Env,
    const uint8_t *Code,
    size_t CodeSize,
    ND_UINT64 Options,
    ND_UINT64 MaxInstructions
    )
{
    SHEMU_CONTEXT *ctx;

    memset(Env, 0, sizeof(*Env));

    Env->ShellSize = CodeSize;
    Env->Shell = calloc(1, CodeSize);
    Env->Stack = calloc(1, TEST_STACK_SIZE);
    Env->Intbuf = calloc(1, CodeSize + TEST_STACK_SIZE);
    if (Env->Shell == NULL || Env->Stack == NULL || Env->Intbuf == NULL)
    {
        EnvDestroy(Env);
        return false;
    }

    memcpy(Env->Shell, Code, CodeSize);

    ctx = &Env->Ctx;

    ctx->ArchType = SHEMU_ARCH_TYPE_X86;
    ctx->Shellcode = Env->Shell;
    ctx->Stack = Env->Stack;
    ctx->Intbuf = Env->Intbuf;

    ctx->ShellcodeBase = TEST_SHELL_BASE;
    ctx->ShellcodeSize = CodeSize;
    ctx->StackBase = TEST_STACK_BASE;
    ctx->StackSize = TEST_STACK_SIZE;
    ctx->IntbufSize = CodeSize + TEST_STACK_SIZE;

    ctx->Arch.X86.Mode = ND_CODE_64;
    ctx->Arch.X86.Ring = 3;

    // Long-mode, ring 3 selectors.
    ctx->Arch.X86.Segments.Cs.Selector = 0x33;
    ctx->Arch.X86.Segments.Ds.Selector = 0x2b;
    ctx->Arch.X86.Segments.Es.Selector = 0x2b;
    ctx->Arch.X86.Segments.Ss.Selector = 0x2b;
    ctx->Arch.X86.Segments.Fs.Selector = 0x53;
    ctx->Arch.X86.Segments.Gs.Selector = 0x53;
    ctx->Arch.X86.Segments.Gs.Base = TEST_TIB_BASE;

    ctx->Arch.X86.Registers.RegRip = TEST_SHELL_BASE;
    ctx->Arch.X86.Registers.RegRsp = TEST_STACK_BASE + TEST_STACK_SIZE / 2;
    ctx->Arch.X86.Registers.RegFlags = NDR_RFLAG_IF | 2;

    ctx->TibBase = TEST_TIB_BASE;
    ctx->MaxInstructionsCount = MaxInstructions;
    ctx->Options = Options;

    ctx->NopThreshold = SHEMU_DEFAULT_NOP_THRESHOLD;
    ctx->StrThreshold = SHEMU_DEFAULT_STR_THRESHOLD;
    ctx->MemThreshold = SHEMU_DEFAULT_MEM_THRESHOLD;

    // No Log callback: the tests never rely on textual emulator output.
    ctx->AccessMemory = UnhandledExternalAccess;

    return true;
}


//
// Run the image once with the given instruction budget. When ShellOut is
// non-NULL it receives a copy of the (possibly modified) shellcode image.
//
static bool
RunOnce(
    const uint8_t *Code,
    size_t CodeSize,
    ND_UINT64 Options,
    ND_UINT64 Budget,
    TRACE_STEP *Step,
    uint8_t *ShellOut,
    ND_UINT64 *FlagsOut,
    ND_UINT64 *UniqueOut
    )
{
    EMU_ENV env;
    SHEMU_CONTEXT *ctx;

    if (!EnvInit(&env, Code, CodeSize, Options, Budget))
    {
        return false;
    }

    ctx = &env.Ctx;
    Step->Status = ShemuX86Emulate(ctx);

    // Note: RIP is advanced before an instruction emulates, so RIP-length
    // recovers the fetch address only for non-control-flow instructions; for
    // taken branches RIP is the branch target. CollectTrace derives fetch
    // addresses from the previous run's RIP instead, which is always correct.
    Step->Length = ctx->Arch.X86.Instruction.Length;
    Step->NextRip = ctx->Arch.X86.Registers.RegRip;
    Step->Addr = Step->NextRip - Step->Length;
    Step->Count = ctx->InstructionsCount;

    if (ShellOut != NULL)
    {
        memcpy(ShellOut, env.Shell, CodeSize);
    }
    if (FlagsOut != NULL)
    {
        *FlagsOut = ctx->Flags;
    }
    if (UniqueOut != NULL)
    {
        *UniqueOut = ctx->UniqueCount;
    }

    EnvDestroy(&env);
    return true;
}


//
// Rebuild the executed-instruction trace by re-running with budgets 1..Steps.
// Each entry's Addr is the fetch address of the instruction decoded in that
// run, i.e. the RIP left by the previous run after its last instruction. If a
// run aborts while fetching its next instruction (RIP outside the image), no
// new instruction is decoded, so Addr keeps the previous entry's address and
// the aborted target remains available in NextRip.
//
static bool
CollectTrace(
    const uint8_t *Code,
    size_t CodeSize,
    ND_UINT64 Options,
    unsigned int Steps,
    TRACE_STEP *Trace
    )
{
    ND_UINT64 nextRip = TEST_SHELL_BASE;

    for (unsigned int i = 0; i < Steps; i++)
    {
        ND_UINT64 fetchRip = nextRip;

        if (!RunOnce(Code, CodeSize, Options, (ND_UINT64)i + 1, &Trace[i],
                     NULL, NULL, NULL))
        {
            return false;
        }

        if (Trace[i].Status == SHEMU_ABORT_RIP_OUTSIDE ||
            Trace[i].Status == SHEMU_ABORT_FETCH_ERROR ||
            Trace[i].Status == SHEMU_ABORT_DECODE_ERROR)
        {
            // Nothing was decoded; anchor to the previous fetched instruction.
            Trace[i].Addr = i == 0 ? TEST_SHELL_BASE : Trace[i - 1].Addr;
        }
        else
        {
            Trace[i].Addr = fetchRip;
        }

        nextRip = Trace[i].NextRip;
    }

    return true;
}


static bool
TraceHasOffset(
    const TRACE_STEP *Trace,
    unsigned int Steps,
    ND_UINT64 Offset
    )
{
    for (unsigned int i = 0; i < Steps; i++)
    {
        if (Trace[i].Addr == TEST_SHELL_BASE + Offset)
        {
            return true;
        }
    }

    return false;
}


//
// Test 1: a word store rewrites two bytes that are subsequently fetched. The
// rewritten bytes decode as one-byte NOPs; a UD2 placed after the modified
// range terminates emulation. A UD2 in the skipped branch is never executed.
//
// Layout (base = TEST_SHELL_BASE):
//   00: 66 C7 05 06 00 00 00 90 90   mov word [rip+6], 0x9090  (-> 15..16)
//   09: EB 04                        jmp +4                     (-> 15)
//   0B: 0F 0B                        ud2 (skipped)
//   0D: 00 00                        padding
//   0F: 0F 0B                        ud2, rewritten to 90 90 (nop, nop)
//   11: 0F 0B                        ud2 terminator
//
static void
TestWriteThenFetch(
    void
    )
{
    static const size_t codeSize = 20;
    uint8_t code[20] = {
        0x66, 0xC7, 0x05, 0x06, 0x00, 0x00, 0x00, 0x90, 0x90,
        0xEB, 0x04,
        0x0F, 0x0B,
        0x00, 0x00,
        0x0F, 0x0B,
        0x0F, 0x0B,
    };
    uint8_t finalShell[20];
    ND_UINT64 flags = 0, unique = 0;
    TRACE_STEP last = { 0 };
    TRACE_STEP trace[5];

    printf("TestWriteThenFetch: store must be visible to later fetches\n");

    //
    // Normal run: self-writes are committed.
    //
    CHECK(RunOnce(code, codeSize, 0, 64, &last, finalShell, &flags, &unique),
          "emulator run failed");

    CHECK(last.Status == SHEMU_ABORT_CANT_EMULATE,
          "expected CANT_EMULATE on UD2 terminator, got 0x%08x", last.Status);
    CHECK(last.Count == 5, "expected 5 emulated instructions, got %llu",
          (unsigned long long)last.Count);
    CHECK(unique == 5, "expected 5 unique addresses, got %llu",
          (unsigned long long)unique);
    CHECK(last.NextRip == TEST_SHELL_BASE + 0x13,
          "expected RIP 0x%llx after terminating UD2, got 0x%llx",
          (unsigned long long)(TEST_SHELL_BASE + 0x13),
          (unsigned long long)last.NextRip);
    CHECK(last.Addr == TEST_SHELL_BASE + 0x11 && last.Length == 2,
          "last instruction must be the UD2 at offset 0x11, got addr 0x%llx len %u",
          (unsigned long long)last.Addr, last.Length);

    // The modified bytes must hold the stored values.
    CHECK(finalShell[0x0f] == 0x90 && finalShell[0x10] == 0x90,
          "self-write not committed: bytes 0x0f/0x10 = 0x%02x 0x%02x",
          finalShell[0x0f], finalShell[0x10]);
    // The terminator is outside the written range and must be untouched.
    CHECK(finalShell[0x11] == 0x0F && finalShell[0x12] == 0x0B,
          "bytes outside the written range were modified");
    // Everything before the target must be unchanged.
    CHECK(memcmp(finalShell, code, 0x0f) == 0,
          "unexpected modification before the write target");

    // Executing previously written bytes must raise the self-write flag.
    CHECK((flags & SHEMU_FLAG_WRITE_SELF) != 0,
          "SHEMU_FLAG_WRITE_SELF not set after executing modified bytes");

    //
    // Reconstruct the full executed-address / length trace.
    //
    CHECK(CollectTrace(code, codeSize, 0, 5, trace), "trace collection failed");

    static const struct
    {
        ND_UINT64 Offset;
        ND_UINT8  Length;
    } expected[5] = {
        { 0x00, 9 },   // mov word [rip+6], 0x9090
        { 0x09, 2 },   // jmp +4
        { 0x0f, 1 },   // rewritten nop
        { 0x10, 1 },   // rewritten nop
        { 0x11, 2 },   // ud2 terminator
    };

    for (unsigned int i = 0; i < 5; i++)
    {
        CHECK(trace[i].Addr == TEST_SHELL_BASE + expected[i].Offset,
              "trace step %u fetched from 0x%llx, expected offset 0x%llx",
              i, (unsigned long long)trace[i].Addr,
              (unsigned long long)expected[i].Offset);
        CHECK(trace[i].Length == expected[i].Length,
              "trace step %u length %u, expected %u",
              i, trace[i].Length, expected[i].Length);
    }

    // Budgets 1..4 stop because the budget is exhausted; budget 5 hits UD2.
    // The loop counter is post-incremented, so an exhausted-budget run of
    // N instructions reports InstructionsCount == N + 1.
    for (unsigned int i = 0; i < 4; i++)
    {
        CHECK(trace[i].Status == SHEMU_SUCCESS,
              "trace step %u expected SUCCESS (budget exhausted), got 0x%08x",
              i, trace[i].Status);
        CHECK(trace[i].Count == (ND_UINT64)i + 2,
              "trace step %u count %llu, expected %u",
              i, (unsigned long long)trace[i].Count, i + 2);
    }
    CHECK(trace[4].Status == SHEMU_ABORT_CANT_EMULATE,
          "final trace step expected CANT_EMULATE, got 0x%08x",
          trace[4].Status);

    // The UD2 in the skipped branch must never appear in the trace.
    CHECK(!TraceHasOffset(trace, 5, 0x0b),
          "skipped UD2 at offset 0x0b was executed");

    //
    // Control run: bypass self-writes. The same control flow must now fetch
    // the original UD2 bytes at offset 0x0f.
    //
    CHECK(RunOnce(code, codeSize, SHEMU_OPT_BYPASS_SELF_WRITES, 64, &last,
                  finalShell, &flags, &unique),
          "bypass run failed");

    CHECK(last.Status == SHEMU_ABORT_CANT_EMULATE,
          "bypass: expected CANT_EMULATE on original UD2, got 0x%08x",
          last.Status);
    CHECK(last.Addr == TEST_SHELL_BASE + 0x0f && last.Length == 2,
          "bypass: original UD2 boundary not preserved (addr 0x%llx len %u)",
          (unsigned long long)last.Addr, last.Length);
    CHECK(last.NextRip == TEST_SHELL_BASE + 0x11,
          "bypass: unexpected RIP 0x%llx", (unsigned long long)last.NextRip);
    CHECK(last.Count == 3, "bypass: expected 3 instructions, got %llu",
          (unsigned long long)last.Count);
    CHECK(finalShell[0x0f] == 0x0F && finalShell[0x10] == 0x0B,
          "bypass: discarded store modified the image (0x%02x 0x%02x)",
          finalShell[0x0f], finalShell[0x10]);
}


//
// Test 2: modification crossing an instruction boundary / overlapping
// instructions. The target originally contains a single 2-byte UD2 (0F 0B);
// a word store overwrites both bytes with one-byte NOPs (90 90), so the fetch
// at the same address now decodes two separate one-byte instructions instead
// of one two-byte instruction. Execution then reaches a second UD2 placed
// immediately after, proving the emulator re-decodes the freshly written bytes
// rather than caching the original instruction boundary.
//
// Layout:
//   00: 66 C7 05 04 00 00 00 90 90   mov word [rip+4], 0x9090  (-> 13..14)
//   09: EB 02                        jmp +2                     (-> 13)
//   0B: 00 00                        skipped bytes
//   0D: 0F 0B                        ud2, rewritten to nop, nop
//   0F: 0F 0B                        ud2 terminator
//
static void
TestOverlappingCrossBoundary(
    void
    )
{
    static const size_t codeSize = 17;
    uint8_t code[17] = {
        0x66, 0xC7, 0x05, 0x04, 0x00, 0x00, 0x00, 0x90, 0x90,
        0xEB, 0x02,
        0x00, 0x00,
        0x0F, 0x0B,
        0x0F, 0x0B,
    };
    uint8_t finalShell[17];
    ND_UINT64 flags = 0, unique = 0;
    TRACE_STEP last = { 0 };
    TRACE_STEP trace[5];

    printf("TestOverlappingCrossBoundary: cross-boundary rewrite changes decode\n");

    CHECK(RunOnce(code, codeSize, 0, 64, &last, finalShell, &flags, &unique),
          "emulator run failed");

    CHECK(last.Status == SHEMU_ABORT_CANT_EMULATE,
          "expected CANT_EMULATE on the UD2 reached after the rewritten stream, "
          "got 0x%08x", last.Status);
    // mov, jmp, nop, nop, ud2.
    CHECK(last.Count == 5, "expected 5 instructions, got %llu",
          (unsigned long long)last.Count);
    CHECK(unique == 5, "expected 5 unique addresses, got %llu",
          (unsigned long long)unique);

    // Only the two target bytes change.
    CHECK(finalShell[0x0d] == 0x90 && finalShell[0x0e] == 0x90,
          "cross-boundary write not committed (0x%02x 0x%02x)",
          finalShell[0x0d], finalShell[0x0e]);
    // The terminator immediately after the target must be untouched.
    CHECK(finalShell[0x0f] == 0x0F && finalShell[0x10] == 0x0B,
          "write exceeded its 2-byte range");

    CHECK((flags & SHEMU_FLAG_WRITE_SELF) != 0,
          "SHEMU_FLAG_WRITE_SELF not set after executing rewritten bytes");

    CHECK(CollectTrace(code, codeSize, 0, 5, trace), "trace collection failed");

    static const struct
    {
        ND_UINT64 Offset;
        ND_UINT8  Length;
    } expected[5] = {
        { 0x00, 9 },   // mov word [rip+4], 0x9090
        { 0x09, 2 },   // jmp +2
        { 0x0d, 1 },   // first byte of the rewritten word: nop
        { 0x0e, 1 },   // second byte, a new instruction boundary: nop
        { 0x0f, 2 },   // ud2 terminator
    };

    for (unsigned int i = 0; i < 5; i++)
    {
        CHECK(trace[i].Addr == TEST_SHELL_BASE + expected[i].Offset,
              "trace step %u fetched from 0x%llx, expected offset 0x%llx",
              i, (unsigned long long)trace[i].Addr,
              (unsigned long long)expected[i].Offset);
        CHECK(trace[i].Length == expected[i].Length,
              "trace step %u length %u, expected %u",
              i, trace[i].Length, expected[i].Length);
    }
    CHECK(trace[4].Status == SHEMU_ABORT_CANT_EMULATE,
          "final trace step expected CANT_EMULATE, got 0x%08x",
          trace[4].Status);
    CHECK(!TraceHasOffset(trace, 5, 0x0b) && !TraceHasOffset(trace, 5, 0x0c),
          "skipped bytes between jmp and target were executed");

    //
    // Control run with self-writes bypassed: the original 2-byte UD2 boundary
    // must be preserved, so emulation stops at the first target instruction.
    //
    CHECK(RunOnce(code, codeSize, SHEMU_OPT_BYPASS_SELF_WRITES, 64, &last,
                  finalShell, &flags, &unique),
          "bypass run failed");

    CHECK(finalShell[0x0d] == 0x0F && finalShell[0x0e] == 0x0B,
          "bypass: image modified despite SHEMU_OPT_BYPASS_SELF_WRITES");
    CHECK(last.Status == SHEMU_ABORT_CANT_EMULATE,
          "bypass: expected CANT_EMULATE on the original UD2, got 0x%08x",
          last.Status);
    // mov, jmp, original ud2 => 3 emulated instructions.
    CHECK(last.Count == 3, "bypass: expected 3 instructions, got %llu",
          (unsigned long long)last.Count);
    // Note: SHEMU_FLAG_WRITE_SELF is derived from the dirty-byte bitmap, which
    // is maintained independently of the SHEMU_OPT_BYPASS_SELF_WRITES store
    // suppression, so its presence/absence is not asserted here.

    TRACE_STEP bypassTrace[3];
    CHECK(CollectTrace(code, codeSize, SHEMU_OPT_BYPASS_SELF_WRITES, 3,
                       bypassTrace),
          "bypass trace collection failed");
    CHECK(bypassTrace[2].Addr == TEST_SHELL_BASE + 0x0d &&
              bypassTrace[2].Length == 2,
          "bypass: original 2-byte UD2 boundary not preserved "
          "(addr 0x%llx len %u)",
          (unsigned long long)bypassTrace[2].Addr,
          bypassTrace[2].Length);
}


//
// Test 3a: a store fully outside the shellcode/stack ranges must abort with
// SHEMU_ABORT_GLA_OUTSIDE and must not modify the image.
//
// Layout:
//   00: 48 C7 C0 00 10 00 00   mov rax, 0x1000
//   07: C6 00 CC               mov byte [rax], 0xCC
//   0A: 0F 0B                  ud2 (must not be reached)
//
static void
TestOutOfBoundsStore(
    void
    )
{
    static const size_t codeSize = 16;
    uint8_t code[16] = {
        0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00,
        0xC6, 0x00, 0xCC,
        0x0F, 0x0B,
    };
    uint8_t finalShell[16];
    ND_UINT64 flags = 0, unique = 0;
    TRACE_STEP last = { 0 };
    TRACE_STEP trace[2];

    printf("TestOutOfBoundsStore: external store aborts, image untouched\n");

    CHECK(RunOnce(code, codeSize, 0, 64, &last, finalShell, &flags, &unique),
          "emulator run failed");

    CHECK(last.Status == SHEMU_ABORT_GLA_OUTSIDE,
          "expected SHEMU_ABORT_GLA_OUTSIDE, got 0x%08x", last.Status);
    // The faulting store is the second instruction and remains the last one
    // executed, so the executed bytes are fully traceable.
    CHECK(last.Count == 2, "expected 2 instructions counted, got %llu",
          (unsigned long long)last.Count);
    // Both the mov and the faulting store were fetched from distinct addresses.
    CHECK(unique == 2, "expected 2 unique addresses, got %llu",
          (unsigned long long)unique);
    CHECK(last.NextRip == TEST_SHELL_BASE + 0x0a,
          "RIP must point past the faulting store, got 0x%llx",
          (unsigned long long)last.NextRip);
    CHECK((flags & SHEMU_FLAG_WRITE_SELF) == 0,
          "external store unexpectedly raised SHEMU_FLAG_WRITE_SELF");
    CHECK(memcmp(finalShell, code, codeSize) == 0,
          "out-of-bounds store modified the emulated image");

    // Budget 1 executes only the mov; budget 2 reaches the faulting store.
    CHECK(CollectTrace(code, codeSize, 0, 2, trace), "trace collection failed");
    CHECK(trace[0].Status == SHEMU_SUCCESS && trace[0].Count == 2 &&
              trace[0].Addr == TEST_SHELL_BASE,
          "budget-1 trace step incorrect");
    CHECK(trace[1].Status == SHEMU_ABORT_GLA_OUTSIDE &&
              trace[1].Addr == TEST_SHELL_BASE + 0x07 &&
              trace[1].Length == 3,
          "budget-2 trace step does not identify the faulting store");
}


//
// Test 3b: a store that straddles the end of the shellcode buffer must be
// rejected as a whole. A same-shape in-bounds store is run as a control to
// prove the range check - not the store itself - is the cause.
//
// Image size is 16.
//   straddling run: word store at offset 15 (bytes 15..16, 16 is outside)
//   in-bounds run : word store at offset 14 (bytes 14..15, both inside)
//
static void
TestStraddlingStoreVsInBounds(
    void
    )
{
    static const size_t codeSize = 16;
    uint8_t straddle[16] = {
        0x66, 0xC7, 0x05, 0x06, 0x00, 0x00, 0x00, 0x90, 0x90,
        0x0F, 0x0B,
    };
    uint8_t inBounds[16] = {
        0x66, 0xC7, 0x05, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90,
        0x0F, 0x0B,
    };
    uint8_t finalShell[16];
    TRACE_STEP last = { 0 };

    printf("TestStraddlingStoreVsInBounds: boundary store vs. legal self-write\n");

    straddle[15] = 0xCC;
    inBounds[14] = 0xCC;
    inBounds[15] = 0xCC;

    //
    // Straddling store: must fail and commit nothing.
    //
    CHECK(RunOnce(straddle, codeSize, 0, 64, &last, finalShell, NULL, NULL),
          "straddling run failed");

    CHECK(last.Status == SHEMU_ABORT_GLA_OUTSIDE,
          "straddling store: expected GLA_OUTSIDE, got 0x%08x", last.Status);
    CHECK(last.Count == 1, "straddling store: expected 1 instruction, got %llu",
          (unsigned long long)last.Count);
    CHECK(last.Addr == TEST_SHELL_BASE && last.Length == 9,
          "straddling store: faulting instruction not traceable");
    CHECK(finalShell[15] == 0xCC,
          "straddling store partially committed (byte 15 = 0x%02x)",
          finalShell[15]);
    CHECK(memcmp(finalShell, straddle, codeSize) == 0,
          "straddling store modified the image");

    //
    // Same store shape, fully in bounds: must commit and continue to the UD2.
    //
    CHECK(RunOnce(inBounds, codeSize, 0, 64, &last, finalShell, NULL, NULL),
          "in-bounds run failed");

    CHECK(last.Status == SHEMU_ABORT_CANT_EMULATE,
          "in-bounds store: expected CANT_EMULATE on following UD2, got 0x%08x",
          last.Status);
    CHECK(last.Count == 2, "in-bounds store: expected 2 instructions, got %llu",
          (unsigned long long)last.Count);
    CHECK(finalShell[14] == 0x90 && finalShell[15] == 0x90,
          "in-bounds store did not commit (0x%02x 0x%02x)",
          finalShell[14], finalShell[15]);
}


//
// Test 3c: control flow that leaves the shellcode buffer. The abort reason
// must be SHEMU_ABORT_RIP_OUTSIDE, distinct from the data-access status, and
// the single executed instruction (the jump) must remain traceable.
//
// Layout (image size 16):
//   00: E9 10 00 00 00   jmp rel 0x10  (next RIP 5 + 0x10 = offset 21)
//   05: 0F 0B            ud2 (must not be reached)
//
static void
TestRipOutside(
    void
    )
{
    static const size_t codeSize = 16;
    uint8_t code[16] = {
        0xE9, 0x10, 0x00, 0x00, 0x00,
        0x0F, 0x0B,
    };
    uint8_t finalShell[16];
    TRACE_STEP last = { 0 };
    TRACE_STEP trace[2];

    printf("TestRipOutside: branch out of the image reports RIP_OUTSIDE\n");

    CHECK(RunOnce(code, codeSize, 0, 64, &last, finalShell, NULL, NULL),
          "emulator run failed");

    CHECK(last.Status == SHEMU_ABORT_RIP_OUTSIDE,
          "expected SHEMU_ABORT_RIP_OUTSIDE, got 0x%08x", last.Status);
    CHECK(last.NextRip == TEST_SHELL_BASE + 0x15,
          "branch target RIP 0x%llx, expected 0x%llx",
          (unsigned long long)last.NextRip,
          (unsigned long long)(TEST_SHELL_BASE + 0x15));
    // The jump is the only emulated instruction; its length is still recorded
    // even though the next fetch failed, so it remains fully traceable.
    CHECK(last.Length == 5,
          "executed jump length not traceable (len %u)", last.Length);
    CHECK(memcmp(finalShell, code, codeSize) == 0,
          "image modified by a control-flow test");

    // Budget 1: jump emulated, budget exhausted before the out-of-range fetch.
    // Budget 2: out-of-range fetch aborts. Both entries keep the jump at the
    // base as the last fetched instruction; the abort target is in NextRip.
    CHECK(CollectTrace(code, codeSize, 0, 2, trace), "trace collection failed");
    CHECK(trace[0].Status == SHEMU_SUCCESS && trace[0].Count == 2 &&
              trace[0].Addr == TEST_SHELL_BASE && trace[0].Length == 5,
          "budget-1 step does not match the executed jump");
    CHECK(trace[1].Status == SHEMU_ABORT_RIP_OUTSIDE &&
              trace[1].Addr == TEST_SHELL_BASE &&
              trace[1].NextRip == TEST_SHELL_BASE + 0x15,
          "budget-2 step lost the executed-jump record or the abort target");
}


int
main(
    void
    )
{
    TestWriteThenFetch();
    TestOverlappingCrossBoundary();
    TestOutOfBoundsStore();
    TestStraddlingStoreVsInBounds();
    TestRipOutside();

    printf("\n%d checks, %d failures\n", gChecks, gFailures);

    return gFailures == 0 ? 0 : 1;
}
