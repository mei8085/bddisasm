/*
 * Stack-string tracking functional tests for bdshemu.
 *
 * These tests do not rely on an external assembler: every shellcode is a hand-assembled byte sequence. They
 * exercise the provenance-based stack-string tracker for consecutive writes, byte-by-byte construction,
 * overlapping and partial stores, unreconstructible bytes, branch convergence, plain constant strings and
 * boundary safety, while ensuring emulation state and previously collected string results are not polluted.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"
#include "bdshemu.h"


#define STACK_SIZE_TEST     0x2000
#define SHELL_BASE          0x200000
#define STACK_BASE          0x100000
#define RSP_INIT            0x101000


static int g_failures;
static int g_checks;


static ND_BOOL
access_memory(
    void *Ctx,
    ND_UINT64 Gla,
    ND_SIZET Size,
    ND_UINT8 *Buffer,
    ND_BOOL Store
    )
{
    (void)Ctx;
    (void)Gla;

    // External loads always read as zero; external stores are discarded.
    if (!Store)
    {
        memset(Buffer, 0, (size_t)Size);
    }

    return ND_TRUE;
}


static void
init_context(
    SHEMU_CONTEXT *ctx,
    ND_UINT8 *shell,
    size_t shellSize,
    ND_UINT8 *stack,
    ND_UINT8 *intbuf,
    ND_UINT8 mode
    )
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->ArchType = SHEMU_ARCH_TYPE_X86;
    ctx->Arch.X86.Mode = mode;
    ctx->Arch.X86.Ring = 3;

    ctx->Shellcode = shell;
    ctx->ShellcodeBase = SHELL_BASE;
    ctx->ShellcodeSize = shellSize;

    ctx->Stack = stack;
    ctx->StackBase = STACK_BASE;
    ctx->StackSize = STACK_SIZE_TEST;

    ctx->Intbuf = intbuf;
    ctx->IntbufSize = shellSize + STACK_SIZE_TEST;

    ctx->Arch.X86.Registers.RegRip = SHELL_BASE;
    ctx->Arch.X86.Registers.RegRsp = RSP_INIT;
    ctx->Arch.X86.Registers.RegFlags = NDR_RFLAG_IF | 2;

    ctx->Arch.X86.Segments.Ss.Selector = mode == ND_CODE_64 ? 0x2b : 0x23;
    ctx->Arch.X86.Segments.Ds.Selector = mode == ND_CODE_64 ? 0x2b : 0x23;
    ctx->Arch.X86.Segments.Es.Selector = mode == ND_CODE_64 ? 0x2b : 0x23;
    ctx->Arch.X86.Segments.Cs.Selector = mode == ND_CODE_64 ? 0x33 : 0x1b;
    ctx->Arch.X86.Segments.Fs.Selector = 0x30;
    ctx->Arch.X86.Segments.Fs.Base = 0x7FFF0000;
    ctx->Arch.X86.Segments.Gs.Selector = mode == ND_CODE_64 ? 0x53 : 0x23;
    ctx->Arch.X86.Segments.Gs.Base = mode == ND_CODE_64 ? 0x7FFF0000 : 0;

    ctx->TibBase = 0x7FFF0000;
    ctx->MaxInstructionsCount = 4096;
    ctx->Options = SHEMU_OPT_TRACE_STRINGS;
    ctx->AccessMemory = access_memory;

    ctx->NopThreshold = SHEMU_DEFAULT_NOP_THRESHOLD;
    ctx->StrThreshold = SHEMU_DEFAULT_STR_THRESHOLD;
    // Allow a handful of external (discarded / zero-filled) accesses before aborting.
    ctx->MemThreshold = 16;
}


static void
check_impl(
    bool condition,
    const char *name
    )
{
    g_checks++;
    if (condition)
    {
        printf("  [PASS] %s\n", name);
    }
    else
    {
        g_failures++;
        printf("  [FAIL] %s\n", name);
    }
}

#define check(cond) check_impl((cond), #cond)


static bool
find_string(
    SHEMU_CONTEXT *ctx,
    const char *expected,
    SHEMU_STRING *out
    )
{
    size_t len = strlen(expected);

    for (ND_UINT32 i = 0; i < ctx->StringsCount; i++)
    {
        SHEMU_STRING *s = &ctx->Strings[i];

        if (s->ValidLength == len && memcmp(s->Buffer, expected, len) == 0)
        {
            if (out != NULL)
            {
                *out = *s;
            }
            return true;
        }
    }

    return false;
}


/*
 * Canonical "Hello World" (11 bytes) built at [esp] through immediate stores of mixed widths, followed by a NUL
 * at [esp+11], then esp is materialized into eax and int3 stops emulation.
 *
 *  mov dword [esp], "Hell"
 *  mov word  [esp+4], "o "
 *  mov byte  [esp+6], 'W'
 *  mov byte  [esp+7], 'o'
 *  mov byte  [esp+8], 'r'
 *  mov byte  [esp+9], 'l'
 *  mov byte  [esp+10], 'd'
 *  mov byte  [esp+11], 0
 *  mov eax, esp
 *  int3
 */
static const ND_UINT8 hello_world_stores[] = {
    0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C,             // mov dword [esp], 0x6c6c6548 ("Hell")
    0x66, 0xC7, 0x44, 0x24, 0x04, 0x6F, 0x20,             // mov word [esp+4], 0x206f ("o ")
    0xC6, 0x44, 0x24, 0x06, 0x57,                         // mov byte [esp+6], 'W'
    0xC6, 0x44, 0x24, 0x07, 0x6F,                         // mov byte [esp+7], 'o'
    0xC6, 0x44, 0x24, 0x08, 0x72,                         // mov byte [esp+8], 'r'
    0xC6, 0x44, 0x24, 0x09, 0x6C,                         // mov byte [esp+9], 'l'
    0xC6, 0x44, 0x24, 0x0A, 0x64,                         // mov byte [esp+10], 'd'
    0xC6, 0x44, 0x24, 0x0B, 0x00,                         // mov byte [esp+11], 0 (NUL)
    0x89, 0xE0,                                           // mov eax, esp
    0xCC                                                  // int3
};


/*
 * Test A (32-bit): consecutive word/dword/byte writes build "Hello World" followed by a NUL.
 */
static void
test_consecutive_writes(
    void
    )
{
    ND_UINT8 *shell = calloc(1, sizeof(hello_world_stores));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(hello_world_stores) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, hello_world_stores, sizeof(hello_world_stores));
    init_context(&ctx, shell, sizeof(hello_world_stores), stack, intbuf, ND_CODE_32);

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test A: consecutive mixed-width writes (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hello World", &s));
    check(s.ValidLength == 11);
    check(s.StartAddress == RSP_INIT);
    check(s.NulTerminated == ND_TRUE);
    check(s.SourceStart == SHELL_BASE);
    check(s.SourceEnd > s.SourceStart);
    check(ctx.StringsCount == 1);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test B (32-bit): overlapping and partial writes. A first dword is fully overwritten, an individual byte is
 * partially overwritten, and a final overlapping store closes the string. Provenance must follow the latest
 * stores while the reconstructed content stays "Hello World".
 */
static void
test_overlapping_writes(
    void
    )
{
    static const ND_UINT8 code[] = {
        0xC7, 0x04, 0x24, 0x58, 0x58, 0x58, 0x58,             // mov dword [esp], "XXXX"
        0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C,             // mov dword [esp], "Hell" (full overwrite)
        0xC6, 0x44, 0x24, 0x02, 0x6C,                         // mov byte [esp+2], 'l' (partial overwrite)
        0x66, 0xC7, 0x44, 0x24, 0x04, 0x6F, 0x20,             // mov word [esp+4], "o "
        0xC6, 0x44, 0x24, 0x06, 0x57,                         // 'W'
        0xC6, 0x44, 0x24, 0x07, 0x6F,                         // 'o'
        0xC6, 0x44, 0x24, 0x08, 0x72,                         // 'r'
        0xC6, 0x44, 0x24, 0x09, 0x6C,                         // 'l'
        0xC6, 0x44, 0x24, 0x0A, 0x64,                         // 'd'
        0xC6, 0x44, 0x24, 0x0B, 0x00,                         // NUL
        0x89, 0xE0,
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_32);

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test B: overlapping / partial writes (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hello World", &s));
    check(s.ValidLength == 11);
    check(s.NulTerminated == ND_TRUE);
    // The first dword was fully overwritten, so the earliest surviving origin is the second store (offset 7).
    check(s.SourceStart == SHELL_BASE + 7);
    check(s.SourceEnd > s.SourceStart);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test C (64-bit): unreconstructible bytes must never be turned into printable content. An external load feeds a
 * register of unknown provenance which is stored first; only the region after it is built from constants.
 */
static void
test_unknown_bytes(
    void
    )
{
    static const ND_UINT8 code[] = {
        0x48, 0x8B, 0x1C, 0x25, 0x00, 0x00, 0x40, 0x00,       // mov rbx, [0x400000] (unknown)
        0x48, 0x89, 0x1C, 0x24,                               // mov [rsp], rbx (unknown 8 bytes)
        0xC7, 0x44, 0x24, 0x08, 0x48, 0x65, 0x6C, 0x6C,       // mov dword [rsp+8], "Hell"
        0x66, 0xC7, 0x44, 0x24, 0x0C, 0x6F, 0x20,             // mov word [rsp+12], "o "
        0xC6, 0x44, 0x24, 0x0E, 0x57,                         // 'W' [rsp+14]
        0xC6, 0x44, 0x24, 0x0F, 0x6F,                         // 'o' [rsp+15]
        0xC6, 0x44, 0x24, 0x10, 0x72,                         // 'r' [rsp+16]
        0xC6, 0x44, 0x24, 0x11, 0x6C,                         // 'l' [rsp+17]
        0xC6, 0x44, 0x24, 0x12, 0x64,                         // 'd' [rsp+18]
        0x48, 0x89, 0xE0,                                     // mov rax, rsp
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_64);

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test C: unknown provenance bytes (64-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hello World", &s));
    check(s.StartAddress == RSP_INIT + 8);
    check(s.ValidLength == 11);

    bool startsAtRsp = false;
    for (ND_UINT32 i = 0; i < ctx.StringsCount; i++)
    {
        if (ctx.Strings[i].StartAddress == RSP_INIT)
        {
            startsAtRsp = true;
        }
    }
    check(!startsAtRsp);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test D (32-bit): partial overwrite recovers an unknown byte. An unknown register dword is later overwritten
 * byte-by-byte with known constants; the recovered region must be fully reconstructible again.
 */
static void
test_recovery_after_overwrite(
    void
    )
{
    static const ND_UINT8 code[] = {
        0xA1, 0x00, 0x00, 0x40, 0x00,                         // mov eax, [0x400000] (unknown)
        0x89, 0x04, 0x24,                                     // mov [esp], eax (unknown dword)
        0xC6, 0x04, 0x24, 0x48,                               // mov byte [esp], 'H'
        0xC6, 0x44, 0x24, 0x01, 0x69,                         // mov byte [esp+1], 'i'
        0xC6, 0x44, 0x24, 0x02, 0x78,                         // mov byte [esp+2], 'x'
        0xC6, 0x44, 0x24, 0x03, 0x00,                         // mov byte [esp+3], NUL
        0x89, 0xE0,
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_32);
    ctx.StrThreshold = 3;

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test D: recovery after partial overwrite (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hix", &s));
    check(s.ValidLength == 3);
    check(s.NulTerminated == ND_TRUE);
    check(s.StartAddress == RSP_INIT);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test E (32-bit): branch convergence. The taken branch and the fall-through converge on a common tail that
 * finishes one contiguous string built by multiple instructions.
 */
static void
test_branch_convergence(
    void
    )
{
    static const ND_UINT8 code[] = {
        0x31, 0xC0,                                           // 0x00 xor eax, eax
        0x85, 0xC0,                                           // 0x02 test eax, eax
        0x74, 0x09,                                           // 0x04 jz path_b (target 0x0F)
        0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C,             // 0x06 (path A) mov dword [esp], "Hell"
        0xEB, 0x07,                                           // 0x0D jmp common (target 0x16)
        0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C,             // 0x0F (path B) mov dword [esp], "Hell"
        0x66, 0xC7, 0x44, 0x24, 0x04, 0x6F, 0x20,             // 0x16 mov word [esp+4], "o "
        0xC6, 0x44, 0x24, 0x06, 0x57,                         // 'W'
        0xC6, 0x44, 0x24, 0x07, 0x6F,                         // 'o'
        0xC6, 0x44, 0x24, 0x08, 0x72,                         // 'r'
        0xC6, 0x44, 0x24, 0x09, 0x6C,                         // 'l'
        0xC6, 0x44, 0x24, 0x0A, 0x64,                         // 'd'
        0x89, 0xE0,
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_32);

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test E: branch convergence (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hello World", &s));
    check(s.ValidLength == 11);
    check(s.SourceEnd > s.SourceStart);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test F (32-bit): a plain constant string produced by a single store keeps the legacy representation and does
 * not create a new dynamic entry. The threshold is lowered so the 4-byte constant reaches it.
 */
static void
test_plain_constant_string(
    void
    )
{
    static const ND_UINT8 code[] = {
        0x68, 0x48, 0x65, 0x6C, 0x6C,                         // push "Hell"
        0x89, 0xE0,                                           // mov eax, esp
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_32);
    ctx.StrThreshold = 4;

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test F: single-store constant string keeps legacy representation (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check((ctx.Flags & SHEMU_FLAG_STACK_STR) != 0);
    check(ctx.StringsCount == 0);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test G (32-bit): boundary safety. A store outside the emulated stack is handled externally and must not
 * corrupt tracker state; the valid in-stack construction afterwards still works.
 */
static void
test_boundary_safety(
    void
    )
{
    static const ND_UINT8 code[] = {
        0xC6, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00, 0x41,       // mov byte [0x500000], 'A' (external)
        0xC7, 0x04, 0x24, 0x48, 0x65, 0x6C, 0x6C,             // mov dword [esp], "Hell"
        0x89, 0xE0,
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_32);
    ctx.StrThreshold = 4;

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test G: out-of-stack store boundary safety (32-bit)\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(ctx.StringsCount == 0);
    check((ctx.Flags & SHEMU_FLAG_STACK_STR) != 0);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test H: no pollution across runs. A second emulation over the same context memory must not inherit the first
 * run's collected strings.
 */
static void
test_no_cross_run_pollution(
    void
    )
{
    static const ND_UINT8 codeDynamic[] = {
        0xC6, 0x04, 0x24, 0x48,                               // mov byte [esp], 'H'
        0xC6, 0x44, 0x24, 0x01, 0x69,                         // mov byte [esp+1], 'i'
        0x89, 0xE0,
        0xCC
    };

    static const ND_UINT8 codeConstant[] = {
        0x68, 0x48, 0x65, 0x6C, 0x6C,                         // push "Hell"
        0x89, 0xE0,
        0xCC
    };

    ND_UINT8 *shell = calloc(1, 64);
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, 64 + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    printf("Test H: no pollution across emulation runs\n");

    memcpy(shell, codeDynamic, sizeof(codeDynamic));
    init_context(&ctx, shell, 64, stack, intbuf, ND_CODE_32);
    ctx.StrThreshold = 2;
    SHEMU_STATUS st1 = ShemuEmulate(&ctx);
    check(st1 == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Hi", &s));
    check(ctx.StringsCount >= 1);

    memset(stack, 0, STACK_SIZE_TEST);
    memset(intbuf, 0, 64 + STACK_SIZE_TEST);
    memset(shell, 0, 64);
    memcpy(shell, codeConstant, sizeof(codeConstant));
    init_context(&ctx, shell, 64, stack, intbuf, ND_CODE_32);
    ctx.StrThreshold = 4;

    SHEMU_STATUS st2 = ShemuEmulate(&ctx);
    check(st2 == SHEMU_ABORT_CANT_EMULATE);
    check(ctx.StringsCount == 0);
    check((ctx.Flags & SHEMU_FLAG_STACK_STR) != 0);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test I (16-bit): byte stores in 16-bit mode. Two distinct byte stores build "Ab"; provenance must be tracked
 * regardless of the operand word length.
 */
static void
test_16bit_mode(
    void
    )
{
    static const ND_UINT8 code[] = {
        0x67, 0xC6, 0x04, 0x24, 0x41,                         // mov byte [esp], 'A' (16-bit mode, a32 addr)
        0x67, 0xC6, 0x44, 0x24, 0x01, 0x62,                  // mov byte [esp+1], 'b'
        0x66, 0x89, 0xE0,                                     // mov eax, esp
        0xCC
    };

    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, STACK_SIZE_TEST);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + STACK_SIZE_TEST);
    SHEMU_CONTEXT ctx;
    SHEMU_STRING s;

    memcpy(shell, code, sizeof(code));
    init_context(&ctx, shell, sizeof(code), stack, intbuf, ND_CODE_16);
    ctx.StrThreshold = 2;

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test I: 16-bit mode byte stores\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(find_string(&ctx, "Ab", &s));
    check(s.ValidLength == 2);

    free(shell);
    free(stack);
    free(intbuf);
}


/*
 * Test J: a stack larger than the inline tracking window must not break emulation; tracking is simply disabled,
 * so no dynamic entries are produced while emulation still completes normally.
 */
static void
test_oversized_stack(
    void
    )
{
    static const ND_UINT8 code[] = {
        0xC6, 0x04, 0x24, 0x48,                               // mov byte [esp], 'H'
        0xC6, 0x44, 0x24, 0x01, 0x69,                         // mov byte [esp+1], 'i'
        0x89, 0xE0,
        0xCC
    };

    ND_UINT64 bigStack = SHEMU_STACK_TRACK_MAX_SIZE + 0x1000;
    ND_UINT8 *shell = calloc(1, sizeof(code));
    ND_UINT8 *stack = calloc(1, bigStack);
    ND_UINT8 *intbuf = calloc(1, sizeof(code) + bigStack);
    SHEMU_CONTEXT ctx;

    memcpy(shell, code, sizeof(code));

    memset(&ctx, 0, sizeof(ctx));
    ctx.ArchType = SHEMU_ARCH_TYPE_X86;
    ctx.Arch.X86.Mode = ND_CODE_32;
    ctx.Arch.X86.Ring = 3;
    ctx.Shellcode = shell;
    ctx.ShellcodeBase = SHELL_BASE;
    ctx.ShellcodeSize = sizeof(code);
    ctx.Stack = stack;
    ctx.StackBase = STACK_BASE;
    ctx.StackSize = bigStack;
    ctx.Intbuf = intbuf;
    ctx.IntbufSize = sizeof(code) + bigStack;
    ctx.Arch.X86.Registers.RegRip = SHELL_BASE;
    ctx.Arch.X86.Registers.RegRsp = STACK_BASE + bigStack - 0x100;
    ctx.Arch.X86.Registers.RegFlags = NDR_RFLAG_IF | 2;
    ctx.Arch.X86.Segments.Ss.Selector = 0x23;
    ctx.Arch.X86.Segments.Ds.Selector = 0x23;
    ctx.Arch.X86.Segments.Es.Selector = 0x23;
    ctx.Arch.X86.Segments.Cs.Selector = 0x1b;
    ctx.TibBase = 0x7FFF0000;
    ctx.MaxInstructionsCount = 4096;
    ctx.AccessMemory = access_memory;
    ctx.StrThreshold = 2;
    ctx.MemThreshold = 16;

    SHEMU_STATUS st = ShemuEmulate(&ctx);

    printf("Test J: oversized stack disables tracking safely\n");
    check(st == SHEMU_ABORT_CANT_EMULATE);
    check(ctx.StringsCount == 0);

    free(shell);
    free(stack);
    free(intbuf);
}


int
main(
    void
    )
{
    test_consecutive_writes();
    test_overlapping_writes();
    test_unknown_bytes();
    test_recovery_after_overwrite();
    test_branch_convergence();
    test_plain_constant_string();
    test_boundary_safety();
    test_no_cross_run_pollution();
    test_16bit_mode();
    test_oversized_stack();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
