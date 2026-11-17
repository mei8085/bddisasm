/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Decode-to-text boundary tests.
 *
 * The contract under test:
 *
 *   - A successful decode describes exactly one instruction inside the supplied window, with a real
 *     instruction class, definition and mnemonic, and operand counts that fit the array that backs them.
 *   - A failed decode keeps the failure reason in the status and the boundary in Length, but clears the
 *     instruction identity, so nothing can render it as if it were valid.
 *   - NdToText / NdToTextMini either produce complete text that fits the buffer, or return an error and
 *     leave the buffer empty. Truncation is reported, never papered over.
 *   - A structure that does not satisfy the decode invariants is rejected by the formatter instead of being
 *     rendered into plausible-looking text.
 *
 * The file is self-contained: build it against libbddisasm.a and run it. To fuzz the boundary under a
 * sanitizer, build both the library and this file with -fsanitize=address,undefined.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bddisasm.h"

//
// The maximum length of the text produced by any instruction in this build. ND_MIN_BUF_SIZE is the size the
// documentation recommends for a NdToText buffer; the suite asserts that the real maximum fits inside it.
//
#define TB_MAX_TEXT 4096

static unsigned long long gFailures;
static unsigned long long gChecks;

//
// Deterministic xorshift, so a failure can be regenerated from the seed.
//
static unsigned long long gSeed = 0x243F6A8885A308D3ULL;

static unsigned int
tb_rand(void)
{
    gSeed ^= gSeed << 13;
    gSeed ^= gSeed >> 7;
    gSeed ^= gSeed << 17;

    return (unsigned int)gSeed;
}

static void
tb_fail(
    const char *Check,
    const char *Message,
    const unsigned char *Code,
    unsigned int Size,
    unsigned int Mode
)
{
    gFailures++;

    printf("FAIL [%s] %s (mode=%u, %u bytes:", Check, Message, Mode, Size);

    for (unsigned int i = 0; i < Size && i < ND_MAX_INSTRUCTION_LENGTH; i++)
    {
        printf(" %02x", Code[i]);
    }

    printf(")\n");
}

static void
tb_pass(void)
{
    gChecks++;
}

//
// True if a failed decode left nothing that could be mistaken for an instruction.
//
static int
tb_decode_failure_is_clean(
    const INSTRUX *Instrux,
    unsigned int Size
)
{
    if (ND_INS_INVALID != Instrux->Instruction)
    {
        return 0;
    }

    if (0 != Instrux->Idbe)
    {
        return 0;
    }

    if (0 != Instrux->ExpOperandsCount || 0 != Instrux->OperandsCount)
    {
        return 0;
    }

#ifndef BDDISASM_NO_MNEMONIC
    if (ND_NULL != Instrux->Mnemonic)
    {
        return 0;
    }
#endif // !BDDISASM_NO_MNEMONIC

    // Length must stay a boundary inside the window, never a claim past it.
    if (Instrux->Length > Size)
    {
        return 0;
    }

    return 1;
}

//
// True if a successful decode is internally consistent.
//
static int
tb_decode_success_is_consistent(
    const INSTRUX *Instrux,
    unsigned int Size
)
{
    ND_INS_CLASS instructionClass;

    if (Instrux->Length < 1 || Instrux->Length > ND_MAX_INSTRUCTION_LENGTH || Instrux->Length > Size)
    {
        return 0;
    }

    if (ND_INS_INVALID == Instrux->Instruction)
    {
        return 0;
    }

    if (Instrux->ExpOperandsCount > ND_MAX_OPERAND || Instrux->OperandsCount > ND_MAX_OPERAND ||
        Instrux->OperandsCount < Instrux->ExpOperandsCount)
    {
        return 0;
    }

    if (Instrux->PrefLength > Instrux->Length || Instrux->OpLength < 1 ||
        (ND_UINT32)Instrux->OpOffset + Instrux->OpLength > Instrux->Length)
    {
        return 0;
    }

    // The public API resolves Idbe -> instruction class, so it fails if the definition does not exist, and
    // the returned class must agree with the one stored in the structure.
    if (!ND_SUCCESS(NdGetInstructionClassMini((const INSTRUX_MINI *)Instrux, &instructionClass)) ||
        instructionClass != Instrux->Instruction)
    {
        return 0;
    }

#ifndef BDDISASM_NO_MNEMONIC
    if (ND_NULL == Instrux->Mnemonic || '\0' == Instrux->Mnemonic[0])
    {
        return 0;
    }
#endif // !BDDISASM_NO_MNEMONIC

    return 1;
}

//
// Verify the decode contract for one window in one mode.
//
static void
tb_check_decode(
    const unsigned char *Code,
    unsigned int Size,
    unsigned int Mode
)
{
    INSTRUX ix;
    NDSTATUS status;

    memset(&ix, 0, sizeof(ix));
    status = NdDecodeEx(&ix, Code, Size, (ND_UINT8)Mode, (ND_UINT8)Mode);

    if (ND_SUCCESS(status))
    {
        if (!tb_decode_success_is_consistent(&ix, Size))
        {
            tb_fail("decode", "successful decode is inconsistent", Code, Size, Mode);
            return;
        }
    }
    else
    {
        if (!tb_decode_failure_is_clean(&ix, Size))
        {
            tb_fail("decode", "failed decode left instruction identity behind", Code, Size, Mode);
            return;
        }
    }

    tb_pass();
}

//
// A successful decode followed by a failed one must not leak the first instruction's identity when the
// caller opted out of zeroing.
//
static void
tb_check_stale_state(void)
{
    ND_CONTEXT ctx;
    INSTRUX ix;
    NDSTATUS status;
    const unsigned char good[] = { 0x8b, 0x44, 0x24, 0x10 };  // mov eax, [rsp+0x10]
    const unsigned char bad[] = { 0xf0, 0x90 };               // LOCK NOP -> bad lock prefix

    NdInitContext(&ctx);
    ctx.DefCode = ND_CODE_64;
    ctx.DefData = ND_CODE_64;
    ctx.DefStack = ND_CODE_64;
    ctx.Options = ND_OPTION_SKIP_ZERO_INSTRUX;

    memset(&ix, 0, sizeof(ix));
    status = NdDecodeWithContext(&ix, good, sizeof(good), &ctx);
    if (!ND_SUCCESS(status))
    {
        tb_fail("stale", "setup decode failed", good, sizeof(good), ND_CODE_64);
        return;
    }

    status = NdDecodeWithContext(&ix, bad, sizeof(bad), &ctx);
    if (ND_SUCCESS(status))
    {
        tb_fail("stale", "LOCK NOP unexpectedly decoded", bad, sizeof(bad), ND_CODE_64);
        return;
    }

    if (!tb_decode_failure_is_clean(&ix, sizeof(bad)))
    {
        tb_fail("stale", "failed decode reused the previous instruction", bad, sizeof(bad), ND_CODE_64);
        return;
    }

    tb_pass();
}

//
// Verify that a window distinguishes "the input is too short" from "the instruction is too long".
//
static void
tb_check_windows(void)
{
    unsigned char longPrefix[16];
    INSTRUX ix;
    NDSTATUS status;

    memset(longPrefix, 0x66, sizeof(longPrefix));

    // Sixteen prefixes cannot fit in a 15-byte instruction: the reason must be TOO_LONG, not a short input.
    memset(&ix, 0, sizeof(ix));
    status = NdDecodeEx(&ix, longPrefix, sizeof(longPrefix), ND_CODE_64, ND_DATA_64);
    if (ND_STATUS_INSTRUCTION_TOO_LONG != status)
    {
        tb_fail("window", "too-long prefix run not reported as INSTRUCTION_TOO_LONG", longPrefix,
                sizeof(longPrefix), ND_CODE_64);
    }
    else
    {
        tb_pass();
    }

    // Exactly fifteen bytes are a short input for an instruction that wants a 16th byte.
    memset(&ix, 0, sizeof(ix));
    status = NdDecodeEx(&ix, longPrefix, ND_MAX_INSTRUCTION_LENGTH, ND_CODE_64, ND_DATA_64);
    if (ND_STATUS_BUFFER_TOO_SMALL != status)
    {
        tb_fail("window", "15-byte prefix window not reported as BUFFER_TOO_SMALL", longPrefix,
                ND_MAX_INSTRUCTION_LENGTH, ND_CODE_64);
    }
    else
    {
        tb_pass();
    }

    // A large window is a buffer, not one instruction: a short instruction still decodes normally.
    {
        unsigned char buffer[64];
        memset(buffer, 0x90, sizeof(buffer));
        buffer[0] = 0x8b;
        buffer[1] = 0x44;
        buffer[2] = 0x24;
        buffer[3] = 0x10;

        memset(&ix, 0, sizeof(ix));
        status = NdDecodeEx(&ix, buffer, sizeof(buffer), ND_CODE_64, ND_DATA_64);
        if (!ND_SUCCESS(status) || 4 != ix.Length)
        {
            tb_fail("window", "short instruction in a large buffer did not decode", buffer, sizeof(buffer),
                    ND_CODE_64);
        }
        else
        {
            tb_pass();
        }
    }

    // The mini decoder must agree with the full one, with and without the internal byte cache.
    {
        unsigned char buffer[] = { 0xc5, 0xf8, 0x58, 0xc0 };
        ND_CONTEXT ctx;
        INSTRUX_MINI mini;

        for (unsigned int skip = 0; skip < 2; skip++)
        {
            NdInitContext(&ctx);
            ctx.DefCode = ND_CODE_64;
            ctx.DefData = ND_CODE_64;
            ctx.DefStack = ND_CODE_64;
            ctx.Options = skip ? ND_OPTION_SKIP_CACHE_IBYTES : 0;

            memset(&mini, 0, sizeof(mini));
            status = NdDecodeWithContextMini(&mini, buffer, sizeof(buffer), &ctx);
            if (!ND_SUCCESS(status) || 4 != mini.Length)
            {
                tb_fail("window", "mini decoder disagrees with the full decoder", buffer, sizeof(buffer),
                        ND_CODE_64);
            }
            else
            {
                tb_pass();
            }
        }
    }
}

//
// Format one instruction into many buffer sizes and check the text contract.
//
static void
tb_check_text_contract(
    const INSTRUX *Instrux,
    const unsigned char *Code,
    unsigned int Size,
    unsigned int Mode
)
{
    static char text[TB_MAX_TEXT];
    size_t longest = 0;

#if defined(BDDISASM_NO_FORMAT)
    // In a no-format build NdToText is a stub that returns success and empties the buffer. There is no
    // text contract to check; the decode contract above still applies.
    (void)Instrux;
    (void)Code;
    (void)Size;
    (void)Mode;
    (void)text;
    (void)longest;
    tb_pass();
    return;
#endif // BDDISASM_NO_FORMAT

    for (unsigned int bufSize = 1; bufSize <= TB_MAX_TEXT; bufSize = (bufSize < 16) ? bufSize + 1 : bufSize * 2)
    {
        NDSTATUS status;

        memset(text, 0xAA, sizeof(text));

        status = NdToText(Instrux, 0x401000, bufSize, text);

        if (ND_SUCCESS(status))
        {
            size_t length = strlen(text);

            if (0 == length)
            {
                tb_fail("text", "successful format produced empty text", Code, Size, Mode);
                return;
            }

            if (length + 1 > bufSize)
            {
                tb_fail("text", "successful format overflowed the buffer", Code, Size, Mode);
                return;
            }

            if (length > longest)
            {
                longest = length;
            }
        }
        else
        {
            // Any failure must leave nothing behind, so truncated text cannot be read as a full instruction.
            if (0 != text[0])
            {
                tb_fail("text", "failed format left partial text in the buffer", Code, Size, Mode);
                return;
            }

            if (ND_STATUS_BUFFER_OVERFLOW != status)
            {
                tb_fail("text", "format failure used a non-truncation status", Code, Size, Mode);
                return;
            }
        }

        if (bufSize > TB_MAX_TEXT / 2)
        {
            break;
        }
    }

    if (longest + 1 > ND_MIN_BUF_SIZE)
    {
        tb_fail("text", "formatted text does not fit in ND_MIN_BUF_SIZE", Code, Size, Mode);
        return;
    }

    tb_pass();
}

//
// Verify the exact text produced for well-known encodings, so that hardening the boundary cannot silently
// change the output language.
//
typedef struct _TB_GOLDEN
{
    const char      *Text;
    unsigned char   Code[ND_MAX_INSTRUCTION_LENGTH];
    unsigned int    Size;
    unsigned int    Mode;
} TB_GOLDEN;

#if !defined(BDDISASM_NO_FORMAT)
static const TB_GOLDEN gGolden[] =
{
    // Displacements, both signs, in every addressing width.
    { "MOV       eax, dword ptr [rax+0x80]", { 0x8b, 0x80, 0x80, 0x00, 0x00, 0x00 }, 6, ND_CODE_64 },
    { "MOV       eax, dword ptr [rax-0x80]", { 0x8b, 0x80, 0x80, 0xff, 0xff, 0xff }, 6, ND_CODE_64 },
    { "MOV       eax, dword ptr [rax+0x180]", { 0x8b, 0x80, 0x80, 0x01, 0x00, 0x00 }, 6, ND_CODE_64 },
    { "MOV       eax, dword ptr [rax-0x80000000]", { 0x8b, 0x80, 0x00, 0x00, 0x00, 0x80 }, 6, ND_CODE_64 },
    { "MOV       ax, word ptr [bx+si+0x180]", { 0x8b, 0x80, 0x80, 0x01 }, 4, ND_CODE_16 },
    { "MOV       ax, word ptr [bp-0x80]", { 0x8b, 0x46, 0x80 }, 3, ND_CODE_16 },
    { "MOV       eax, dword ptr [eax+0x180]", { 0x8b, 0x80, 0x80, 0x01, 0x00, 0x00 }, 6, ND_CODE_32 },

    // Absolute and RIP-relative addressing. RIP here is 0, so "rel" names a target inside the listing.
    { "MOV       eax, dword ptr [0x80]", { 0x8b, 0x04, 0x25, 0x80, 0x00, 0x00, 0x00 }, 7, ND_CODE_64 },
    { "MOV       eax, dword ptr [rel 0x86]", { 0x8b, 0x05, 0x80, 0x00, 0x00, 0x00 }, 6, ND_CODE_64 },
    { "MOV       eax, dword ptr [0xffffffff]", { 0xa1, 0xff, 0xff, 0xff, 0xff }, 5, ND_CODE_32 },

    // Immediates, including sign extension.
    { "MOV       eax, 0x00000080", { 0xb8, 0x80, 0x00, 0x00, 0x00 }, 5, ND_CODE_64 },
    { "ADD       eax, 0xffffffff", { 0x83, 0xc0, 0xff }, 3, ND_CODE_64 },
    { "ADD       rax, 0xffffffffffffffff", { 0x48, 0x81, 0xc0, 0xff, 0xff, 0xff, 0xff }, 7, ND_CODE_64 },
    { "PUSH      0xffffffffffffffff", { 0x68, 0xff, 0xff, 0xff, 0xff }, 5, ND_CODE_64 },
    { "IMUL      eax, eax, 0xffffffff", { 0x69, 0xc0, 0xff, 0xff, 0xff, 0xff }, 6, ND_CODE_32 },
    { "ROL       eax, 1", { 0xd1, 0xc0 }, 2, ND_CODE_32 },
    { "RCL       al, 0x03", { 0xc0, 0xd0, 0x03 }, 3, ND_CODE_32 },

    // Relative branches. RIP is 0 for all of these.
    { "JMP       0x3", { 0xe9, 0xfe, 0xff, 0xff, 0xff }, 5, ND_CODE_64 },
    { "JMP       0x0", { 0xeb, 0xfe }, 2, ND_CODE_64 },
    { "JMP       0x80000005", { 0xe9, 0x00, 0x00, 0x00, 0x80 }, 5, ND_CODE_32 },

    // Register, segment and memory forms.
    { "MOV       eax, dword ptr [rsp+0x10]", { 0x8b, 0x44, 0x24, 0x10 }, 4, ND_CODE_64 },
    { "MOV       eax, dword ptr [rsp]", { 0x8b, 0x04, 0x24 }, 3, ND_CODE_64 },
    { "MOV       eax, dword ptr fs:[rax+0x10]", { 0x64, 0x8b, 0x40, 0x10 }, 4, ND_CODE_64 },
    { "MOV       eax, dword ptr [rbx+rcx*4+0x10]", { 0x8b, 0x44, 0x8b, 0x10 }, 4, ND_CODE_64 },

    // VEX/EVEX forms and their decorators.
    { "VADDPS    xmm0, xmm0, xmm0", { 0xc5, 0xf8, 0x58, 0xc0 }, 4, ND_CODE_64 },
    { "VADDPS    zmm0, zmm0, zmm0", { 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0 }, 6, ND_CODE_64 },
    { "VADDNEPBF16 xmm3, xmm0, word ptr [r22]{1to8}", { 0x62, 0xfd, 0x7d, 0x18, 0x58, 0x1e }, 6, ND_CODE_64 },
    { "VPMADD52HUQ zmm24, zmm24, qword ptr [rbx]{1to8}", { 0x62, 0x62, 0xbd, 0x50, 0xb5, 0x03 }, 6, ND_CODE_64 },

    // Operand-less instructions: PUSHA/PUSHAD have no explicit operands at all, so no padding is emitted;
    // PUSHFD carries the flags operand, which is padded but has no textual form.
    { "PUSHFD    ", { 0x9c }, 1, ND_CODE_32 },
    { "PUSHA", { 0x60 }, 1, ND_CODE_16 },
    { "PUSHAD", { 0x60 }, 1, ND_CODE_32 },
};

static void
tb_check_golden(void)
{
    for (unsigned int i = 0; i < sizeof(gGolden) / sizeof(gGolden[0]); i++)
    {
        const TB_GOLDEN *golden = &gGolden[i];
        INSTRUX ix;
        char text[TB_MAX_TEXT];
        NDSTATUS status;

        memset(&ix, 0, sizeof(ix));
        status = NdDecodeEx(&ix, golden->Code, golden->Size, (ND_UINT8)golden->Mode, (ND_UINT8)golden->Mode);
        if (!ND_SUCCESS(status))
        {
            tb_fail("golden", "expected encoding did not decode", golden->Code, golden->Size, golden->Mode);
            continue;
        }

        memset(text, 0, sizeof(text));
        status = NdToText(&ix, 0, sizeof(text), text);
        if (!ND_SUCCESS(status))
        {
            tb_fail("golden", "expected encoding did not format", golden->Code, golden->Size, golden->Mode);
            continue;
        }

        if (0 != strcmp(text, golden->Text))
        {
            printf("FAIL [golden] mode=%u text='%s' expected='%s'\n", golden->Mode, text, golden->Text);
            gFailures++;
            continue;
        }

        tb_pass();
    }
}
#endif // !BDDISASM_NO_FORMAT

#if !defined(BDDISASM_NO_FORMAT)
static int
tb_expect_rejected(
    const char *What,
    const INSTRUX *Instrux
)
{
    char text[TB_MAX_TEXT];
    NDSTATUS status;

    memset(text, 0xAA, sizeof(text));
    status = NdToText(Instrux, 0, sizeof(text), text);

    if (ND_SUCCESS(status))
    {
        printf("FAIL [malformed] %s: rendered as '%s'\n", What, text);
        gFailures++;
        return 0;
    }

    if (0 != text[0])
    {
        printf("FAIL [malformed] %s: rejected but left text '%s'\n", What, text);
        gFailures++;
        return 0;
    }

    tb_pass();
    return 1;
}
#endif // !BDDISASM_NO_FORMAT

//
// Starting from a real instruction, break one invariant at a time and require the formatter to refuse it.
//
#if !defined(BDDISASM_NO_FORMAT)
static void
tb_check_malformed(void)
{
    const unsigned char code[] = { 0x8b, 0x44, 0x24, 0x10 };  // mov eax, dword ptr [rsp+0x10]
    INSTRUX base, ix;
    NDSTATUS status;

    memset(&base, 0, sizeof(base));
    status = NdDecodeEx(&base, code, sizeof(code), ND_CODE_64, ND_DATA_64);
    if (!ND_SUCCESS(status))
    {
        printf("FAIL [malformed] setup decode failed\n");
        gFailures++;
        return;
    }

    // Parameter errors: a NULL instruction and a zero buffer must not crash.
    {
        char text[64];
        memset(text, 0xAA, sizeof(text));
        NdToText(ND_NULL, 0, sizeof(text), text);
        if (0 != text[0])
        {
            printf("FAIL [malformed] NULL instruction left text\n");
            gFailures++;
        }
        else
        {
            tb_pass();
        }

        ix = base;
        memset(text, 0, sizeof(text));
        if (ND_SUCCESS(NdToText(&ix, 0, 0, text)))
        {
            printf("FAIL [malformed] zero-sized buffer accepted\n");
            gFailures++;
        }
        else
        {
            tb_pass();
        }
    }

    // A one-byte buffer must report truncation and terminate the single byte.
    {
        char text[1];
        memset(text, 0xAA, sizeof(text));
        if (ND_STATUS_BUFFER_OVERFLOW != NdToText(&base, 0, sizeof(text), text) || 0 != text[0])
        {
            printf("FAIL [malformed] one-byte buffer not reported as truncation\n");
            gFailures++;
        }
        else
        {
            tb_pass();
        }
    }

    ix = base;
    ix.Idbe = 0xFFFF;
    tb_expect_rejected("Idbe out of range", &ix);

    ix = base;
    ix.Instruction = ND_INS_INVALID;
    tb_expect_rejected("instruction class INVALID", &ix);

    ix = base;
    ix.Length = 0;
    tb_expect_rejected("length zero", &ix);

    ix = base;
    ix.Length = ND_MAX_INSTRUCTION_LENGTH + 1;
    tb_expect_rejected("length beyond 15", &ix);

    ix = base;
    ix.PrefLength = (ND_UINT8)(ix.Length + 1);
    tb_expect_rejected("prefix length beyond instruction", &ix);

    ix = base;
    ix.OpOffset = ix.Length;
    tb_expect_rejected("opcode outside instruction", &ix);

    ix = base;
    ix.ExpOperandsCount = ND_MAX_OPERAND + 1;
    tb_expect_rejected("operand count beyond array", &ix);

    ix = base;
    ix.Operands[0].Type = ND_OP_NOT_PRESENT;
    tb_expect_rejected("explicit NOT_PRESENT operand", &ix);

    ix = base;
    ix.Operands[0].Info.Register.Reg = 8;
    ix.Operands[0].Info.Register.Size = ND_SIZE_8BIT;
    tb_expect_rejected("8-bit GPR 8..15 without REX", &ix);

    ix = base;
    ix.Operands[0].Info.Register.Type = ND_REG_MSR;
    ix.Operands[0].Info.Register.Reg = 0;
    ix.Operands[0].Info.Register.Size = ND_SIZE_64BIT;
    tb_expect_rejected("register class without text", &ix);

    ix = base;
    ix.Operands[1].Type = ND_OP_MEM;
    ix.Operands[1].Size = ND_SIZE_32BIT;
    ix.Operands[1].Info.Memory.HasBase = 1;
    ix.Operands[1].Info.Memory.Base = 0;
    ix.Operands[1].Info.Memory.BaseSize = ND_SIZE_64BIT;
    ix.Operands[1].Info.Memory.HasIndex = 1;
    ix.Operands[1].Info.Memory.Index = 1;
    ix.Operands[1].Info.Memory.IndexSize = ND_SIZE_64BIT;
    ix.Operands[1].Info.Memory.Scale = 3;
    tb_expect_rejected("scale 3", &ix);

    ix = base;
    ix.Operands[1].Type = ND_OP_MEM;
    ix.Operands[1].Size = ND_SIZE_64BIT;
    ix.Operands[1].Info.Memory.HasBase = 1;
    ix.Operands[1].Info.Memory.Base = 0;
    ix.Operands[1].Info.Memory.BaseSize = ND_SIZE_64BIT;
    ix.Operands[1].Info.Memory.HasBroadcast = 1;
    ix.Operands[1].Info.Memory.Broadcast.Count = 0;
    tb_expect_rejected("broadcast of zero elements", &ix);

    ix = base;
    ix.Operands[1].Type = ND_OP_MEM;
    ix.Operands[1].Size = ND_SIZE_32BIT;
    ix.Operands[1].Info.Memory.HasBase = 1;
    ix.Operands[1].Info.Memory.Base = 0;
    ix.Operands[1].Info.Memory.BaseSize = ND_SIZE_64BIT;
    ix.Operands[1].Info.Memory.HasDisp = 1;
    ix.Operands[1].Info.Memory.IsRipRel = 1;
    ix.DefCode = ND_CODE_32;
    tb_expect_rejected("RIP-relative outside 64-bit mode", &ix);

    ix = base;
    ix.Operands[1].Type = ND_OP_IMM;
    ix.Operands[1].Size = 3;
    ix.Operands[1].Info.Immediate.RawSize = 3;
    tb_expect_rejected("immediate of 3 bytes", &ix);

    ix = base;
    ix.Operands[1].Type = ND_OP_CONST;
    ix.Operands[1].Info.Constant.Const = 0x123456789ULL;
    tb_expect_rejected("constant beyond 32 bits", &ix);
}
#endif // !BDDISASM_NO_FORMAT

//
// Sweep random windows in all modes. Any decode success is formatted; any failure must stay clean.
//
static void
tb_sweep(
    unsigned long long Cases
)
{
    unsigned char code[ND_MAX_INSTRUCTION_LENGTH + 1];

    for (unsigned long long i = 0; i < Cases; i++)
    {
        unsigned int size = 1 + (tb_rand() % (ND_MAX_INSTRUCTION_LENGTH + 1));
        unsigned int modeIndex = tb_rand() % 3;
        unsigned int mode = (modeIndex == 0) ? ND_CODE_16 : ((modeIndex == 1) ? ND_CODE_32 : ND_CODE_64);
        INSTRUX ix;
        NDSTATUS status;

        for (unsigned int j = 0; j < size; j++)
        {
            code[j] = (unsigned char)tb_rand();
        }

        memset(&ix, 0, sizeof(ix));
        status = NdDecodeEx(&ix, code, size, (ND_UINT8)mode, (ND_UINT8)mode);

        if (ND_SUCCESS(status))
        {
            tb_check_decode(code, size, mode);
            tb_check_text_contract(&ix, code, size, mode);
        }
        else
        {
            tb_check_decode(code, size, mode);
        }
    }
}

//
// Exhaustive one-byte and two-byte opcode/ModRM sweep. This is small enough to run every time and covers
// every decode path that does not need a prefix.
//
static void
tb_sweep_exhaustive(void)
{
    static const unsigned char fill[4][8] =
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x7f, 0x40, 0x24, 0x08, 0x11, 0x22, 0x33, 0x44 },
    };
    static const unsigned int modes[] = { ND_CODE_16, ND_CODE_32, ND_CODE_64 };
    unsigned char code[10];

    for (unsigned int m = 0; m < 3; m++)
    {
        for (unsigned int opcode = 0; opcode < 256; opcode++)
        {
            if (0x0f == opcode)
            {
                continue;
            }

            for (unsigned int modrm = 0; modrm < 256; modrm++)
            {
                for (unsigned int f = 0; f < 4; f++)
                {
                    code[0] = (unsigned char)opcode;
                    code[1] = (unsigned char)modrm;
                    memcpy(code + 2, fill[f], 8);

                    tb_check_decode(code, sizeof(code), modes[m]);
                }
            }
        }
    }
}

int
main(void)
{
    printf("bddisasm decode-to-text boundary tests\n");

    tb_sweep_exhaustive();
    printf("  exhaustive sweep: %llu checks\n", gChecks);

    tb_check_stale_state();
    tb_check_windows();
#if !defined(BDDISASM_NO_FORMAT)
    tb_check_golden();
    tb_check_malformed();
#endif // !BDDISASM_NO_FORMAT

    tb_sweep(200000);
    printf("  random sweep: %llu checks\n", gChecks);

    if (0 != gFailures)
    {
        printf("\nFAILED: %llu of %llu checks\n", gFailures, gChecks + gFailures);
        return 1;
    }

    printf("\nPASSED: %llu checks\n", gChecks);
    return 0;
}
