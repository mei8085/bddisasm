/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic generator for x86 instruction byte streams.
 *
 * The goal is not to be a full assembler, but to exercise the boundaries that
 * a decoder is most likely to get wrong: legacy prefix runs, the VEX/EVEX/XOP
 * and REX2 payloads, ModRM/SIB/displacement combinations, immediate/relative
 * payload sizes and instruction length limits.
 *
 * Every case is derived from (Seed, Index) only, so a failure found by this
 * generator can always be regenerated from the pair printed in the failure
 * report - no sample files need to be kept around.
 */
#include <string.h>

#include "x86_decode_fuzz.h"

//
// One-byte opcodes that select interesting payload layouts: ModRM variants,
// immediates of every width, relative offsets, moffsets and far addresses.
//
static const unsigned char gLegacyOpcodes[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0F, 0x10,
    0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x68, 0x69, 0x6A,
    0x6B, 0x70, 0x74, 0x80, 0x81, 0x82, 0x83, 0x84, 0x88, 0x89,
    0x8A, 0x8B, 0x8C, 0x8D, 0x8F, 0x90, 0x98, 0x9A, 0xA0, 0xA1,
    0xA2, 0xA3, 0xA4, 0xA8, 0xA9, 0xB0, 0xB8, 0xC0, 0xC1, 0xC2,
    0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xCA, 0xCB, 0xD0, 0xD1, 0xD4,
    0xE0, 0xE3, 0xE8, 0xE9, 0xEA, 0xEB, 0xF6, 0xF7, 0xFE, 0xFF,
};

//
// Two-byte (0F xx) opcodes.
//
static const unsigned char gOpcodes0F[] = {
    0x00, 0x01, 0x05, 0x06, 0x0B, 0x0F, 0x10, 0x11, 0x12, 0x13,
    0x18, 0x1A, 0x1B, 0x1C, 0x1E, 0x28, 0x2A, 0x2B, 0x38, 0x3A,
    0x40, 0x44, 0x4C, 0x50, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x7E, 0x7F, 0xAE, 0xAF, 0xB6, 0xB7, 0xBA, 0xBC, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xE7,
    0xF0, 0xF1, 0xF6, 0xF7, 0xFE, 0xFF,
};

//
// Three-byte 0F 38 / 0F 3A opcodes.
//
static const unsigned char gOpcodes38[] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E,
    0x10, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1D,
    0x1E, 0x20, 0x21, 0x22, 0x28, 0x29, 0x2A, 0x2B, 0x30, 0x31,
    0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B, 0x40, 0x41, 0x42, 0x43,
    0x60, 0x61, 0x62, 0x63, 0xCE, 0xCF, 0xF0, 0xF1, 0xF5, 0xF6,
};

static const unsigned char gOpcodes3A[] = {
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x40, 0x41, 0x42, 0x60, 0x61, 0x62, 0x63,
    0xCE, 0xCF, 0xDF,
};

//
// Legacy prefixes. 0x40..0x4F are REX in 64-bit mode and INC/DEC elsewhere, so
// they are only inserted when generating for 64-bit mode.
//
static const unsigned char gLegacyPrefixes[] = {
    0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65,
};

static const unsigned char gRexPrefixes[] = {
    0x40, 0x41, 0x44, 0x48, 0x4C, 0x4D, 0x4F, 0x4A, 0x4B, 0x4E,
};


void
XdfRngSeed(
    XDF_RNG *Rng,
    unsigned long long Seed
)
{
    // SplitMix64 finalizer, so that nearby seeds do not produce nearby streams.
    Seed += 0x9E3779B97F4A7C15ULL;
    Seed = (Seed ^ (Seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
    Seed = (Seed ^ (Seed >> 27)) * 0x94D049BB133111EBULL;
    Seed = Seed ^ (Seed >> 31);

    Rng->State = Seed ? Seed : 0x9E3779B97F4A7C15ULL;
}

unsigned int
XdfRngNext(
    XDF_RNG *Rng
)
{
    unsigned long long x = Rng->State;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    Rng->State = x;

    return (unsigned int)((x * 0x2545F4914F6CDD1DULL) >> 32);
}

unsigned int
XdfRngRange(
    XDF_RNG *Rng,
    unsigned int Bound
)
{
    if (Bound == 0)
    {
        return 0;
    }

    return XdfRngNext(Rng) % Bound;
}


static unsigned int
XdfPick(
    XDF_RNG *Rng,
    const unsigned char *Table,
    unsigned int Count
)
{
    return Table[XdfRngRange(Rng, Count)];
}


static void
XdfAppend(
    XDF_CASE *Case,
    unsigned int Byte
)
{
    if (Case->Len < XDF_GEN_MAX)
    {
        Case->Bytes[Case->Len++] = (unsigned char)Byte;
    }
}


static void
XdfAppendLegacyPrefixes(
    XDF_RNG *Rng,
    XDF_CASE *Case,
    unsigned int MaxCount
)
{
    unsigned int count = XdfRngRange(Rng, MaxCount + 1);

    for (unsigned int i = 0; i < count; i++)
    {
        if (Case->DefCode == ND_CODE_64 && XdfRngRange(Rng, 4) == 0)
        {
            XdfAppend(Case, XdfPick(Rng, gRexPrefixes, sizeof(gRexPrefixes)));
        }
        else
        {
            XdfAppend(Case, XdfPick(Rng, gLegacyPrefixes, sizeof(gLegacyPrefixes)));
        }
    }
}


//
// Build one case for the requested family. All byte choices come from `Rng`,
// whose state is itself derived from (Seed, Index), so the result is stable.
//
static void
XdfBuildLegacy(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    XdfAppendLegacyPrefixes(Rng, Case, 4);
    XdfAppend(Case, XdfPick(Rng, gLegacyOpcodes, sizeof(gLegacyOpcodes)));

    // ModRM, SIB and displacement soup.
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));

    // Immediate-ish tail.
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildOpcode38(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    static const unsigned char map38 = 0x38;
    static const unsigned char map3A = 0x3A;

    XdfAppendLegacyPrefixes(Rng, Case, 3);
    XdfAppend(Case, 0x0F);
    XdfAppend(Case, XdfRngRange(Rng, 2) ? map38 : map3A);

    if (Case->Bytes[Case->Len - 1] == map38)
    {
        XdfAppend(Case, XdfPick(Rng, gOpcodes38, sizeof(gOpcodes38)));
    }
    else
    {
        XdfAppend(Case, XdfPick(Rng, gOpcodes3A, sizeof(gOpcodes3A)));
    }

    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildTwoByte0F(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    XdfAppendLegacyPrefixes(Rng, Case, 3);
    XdfAppend(Case, 0x0F);
    XdfAppend(Case, XdfPick(Rng, gOpcodes0F, sizeof(gOpcodes0F)));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildVex(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // VEX2 or VEX3, occasionally preceded by legacy prefixes (which must be
    // rejected: that is the XDF_TAG_VEX "prefix conflict" boundary).
    if (XdfRngRange(Rng, 4) == 0)
    {
        XdfAppend(Case, XdfPick(Rng, gLegacyPrefixes, sizeof(gLegacyPrefixes)));
    }

    if (XdfRngRange(Rng, 2) == 0)
    {
        XdfAppend(Case, 0xC5);
        XdfAppend(Case, XdfRngNext(Rng));
    }
    else
    {
        XdfAppend(Case, 0xC4);
        XdfAppend(Case, XdfRngNext(Rng));
        XdfAppend(Case, XdfRngNext(Rng));
    }

    // Map-selecting opcode byte, then ModRM/SIB/disp/imm payload.
    XdfAppend(Case, XdfRngRange(Rng, 2) ? XdfPick(Rng, gOpcodes0F, sizeof(gOpcodes0F)) : XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildEvex(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // Regular EVEX, EVEX promoted legacy (map 4), promoted VEX and the
    // conditional/APX flavours all live behind the same 0x62 lead byte, and
    // differ only in payload byte 2/3 bits. Bias the generator towards the
    // discriminator bits so each flavour is actually reached.
    XdfAppendLegacyPrefixes(Rng, Case, 1);

    XdfAppend(Case, 0x62);
    XdfAppend(Case, XdfRngNext(Rng));

    switch (XdfRngRange(Rng, 4))
    {
    case 0:
        // EVEX map 4 (promoted legacy): mmmmm = 4, pp = 0, and byte 3 picks
        // ND/NF/V4 in the legacy layout.
        XdfAppend(Case, (unsigned char)((XdfRngNext(Rng) & 0xF8) | 0x04));
        XdfAppend(Case, (unsigned char)(XdfRngNext(Rng) & 0xE3));
        break;
    case 1:
        // EVEX map 5 (promoted VEX): mmmmm = 5.
        XdfAppend(Case, (unsigned char)((XdfRngNext(Rng) & 0xF8) | 0x05));
        XdfAppend(Case, (unsigned char)(XdfRngNext(Rng) & 0xD3));
        break;
    case 2:
        // Conditional / APX EVEX flavours: map 5 or 6, SC bits in byte 3.
        XdfAppend(Case, (unsigned char)((XdfRngNext(Rng) & 0xF8) | 0x06));
        XdfAppend(Case, (unsigned char)(XdfRngNext(Rng) & 0xE0));
        break;
    default:
        // Regular EVEX, including the mandatory-prefix (pp) and vector
        // length (L'L) fields, plus mask/zero/broadcast bits.
        XdfAppend(Case, XdfRngNext(Rng));
        XdfAppend(Case, XdfRngNext(Rng));
        break;
    }

    XdfAppend(Case, XdfRngRange(Rng, 2) ? XdfPick(Rng, gOpcodes0F, sizeof(gOpcodes0F)) : XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildXop(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // XOP is 0x8F followed by a byte whose low 5 bits are >= 8; anything less
    // makes 0x8F a POP instead, which is itself an interesting boundary.
    XdfAppendLegacyPrefixes(Rng, Case, 2);
    XdfAppend(Case, 0x8F);

    if (XdfRngRange(Rng, 4) == 0)
    {
        XdfAppend(Case, (unsigned char)(XdfRngNext(Rng) & 0x07));
    }
    else
    {
        XdfAppend(Case, (unsigned char)((XdfRngNext(Rng) & 0xF7) | 0x08));
    }

    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildRex2(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // REX2 is 0xD5 in 64-bit mode only; the M0 bit selects the legacy table.
    // Outside 64-bit mode 0xD5 is AAD, another boundary worth hitting.
    if (XdfRngRange(Rng, 8) == 0)
    {
        XdfAppend(Case, XdfPick(Rng, gLegacyPrefixes, sizeof(gLegacyPrefixes)));
    }

    XdfAppend(Case, 0xD5);
    XdfAppend(Case, (unsigned char)(XdfRngNext(Rng) & (XdfRngRange(Rng, 2) ? 0xFF : 0x7F)));
    XdfAppend(Case, XdfRngRange(Rng, 2) ? XdfPick(Rng, gLegacyOpcodes, sizeof(gLegacyOpcodes)) : XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildModRm(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // Exhaustively interesting ModRM values: every mod/rm combination, with
    // SIB and displacement sizes falling out of the encoding rules, and a 0x67
    // address-size override so 16-bit addressing is reached from 32-bit mode.
    static const unsigned char modrms[] = {
        0x00, 0x04, 0x05, 0x0C, 0x40, 0x44, 0x45, 0x7D, 0x80, 0x84,
        0x85, 0xBC, 0xC0, 0xC1, 0xE4, 0xF5, 0xFD, 0xFF,
    };

    if (XdfRngRange(Rng, 3) == 0)
    {
        XdfAppend(Case, 0x67);
    }

    if (Case->DefCode == ND_CODE_64 && XdfRngRange(Rng, 3) == 0)
    {
        XdfAppend(Case, XdfPick(Rng, gRexPrefixes, sizeof(gRexPrefixes)));
    }

    XdfAppend(Case, XdfRngRange(Rng, 2) ? 0x8B : 0x8D);
    XdfAppend(Case, XdfPick(Rng, modrms, sizeof(modrms)));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildImmediate(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // Opcodes whose whole point is a payload of a specific width: immediate,
    // relative offset, moffset or far address. These are the instructions
    // whose decoded Length must exactly cover the payload.
    static const unsigned char immOpcodes[] = {
        0x04, 0x05, 0x68, 0x69, 0x6A, 0x6B, 0x80, 0x81, 0x82, 0x83,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA8, 0xA9, 0xB0, 0xB8, 0xC0, 0xC1,
        0xC2, 0xC6, 0xC7, 0xCA, 0xCD, 0xD4, 0xD5, 0xE4, 0xE5, 0xE6,
        0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0x9A,
    };

    // The 0x66/0x67 prefixes change the operand and address sizes and therefore
    // the byte width of the payload that follows. Both must be reflected in
    // the decoded Length.
    if (XdfRngRange(Rng, 3) == 0)
    {
        XdfAppend(Case, 0x66);
    }
    else if (XdfRngRange(Rng, 3) == 0)
    {
        XdfAppend(Case, 0x67);
    }

    XdfAppend(Case, XdfPick(Rng, immOpcodes, sizeof(immOpcodes)));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildLong(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // Over-long instructions: enough prefixes to cross the 15-byte limit, plus
    // a payload that would otherwise be perfectly decodable. The decoder must
    // stop at the length limit and not read past it.
    unsigned int count = 9 + XdfRngRange(Rng, 12);

    for (unsigned int i = 0; i < count; i++)
    {
        XdfAppend(Case, XdfPick(Rng, gLegacyPrefixes, sizeof(gLegacyPrefixes)));
    }

    XdfAppend(Case, XdfRngRange(Rng, 2) ? 0x90 : XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
    XdfAppend(Case, XdfRngNext(Rng));
}


static void
XdfBuildPrefixOnly(
    XDF_RNG *Rng,
    XDF_CASE *Case
)
{
    // Prefixes and nothing else. Feeding a truncated prefix run is how the
    // "buffer too small" path is exercised in a controlled way.
    unsigned int count = 1 + XdfRngRange(Rng, 15);

    for (unsigned int i = 0; i < count; i++)
    {
        XdfAppend(Case, XdfPick(Rng, gLegacyPrefixes, sizeof(gLegacyPrefixes)));
    }
}


void
XdfGenerateCase(
    unsigned long long Seed,
    unsigned long long Index,
    XDF_CASE *Case
)
{
    XDF_RNG rng;

    memset(Case, 0, sizeof(*Case));

    // Mix the index into the seed so that case N is not simply "seed N".
    XdfRngSeed(&rng, Seed ^ (Index * 0xD1B54A32D192ED03ULL));
    (void)XdfRngNext(&rng);

    Case->Tag = XdfRngRange(&rng, XDF_TAG_MAX);
    Case->DefCode = XdfRngRange(&rng, 3);

    switch (Case->Tag)
    {
    case XDF_TAG_VEX:
        XdfBuildVex(&rng, Case);
        break;
    case XDF_TAG_EVEX:
        XdfBuildEvex(&rng, Case);
        break;
    case XDF_TAG_XOP:
        XdfBuildXop(&rng, Case);
        break;
    case XDF_TAG_MODRM:
        XdfBuildModRm(&rng, Case);
        break;
    case XDF_TAG_IMMEDIATE:
        XdfBuildImmediate(&rng, Case);
        break;
    case XDF_TAG_LONG:
        XdfBuildLong(&rng, Case);
        break;
    case XDF_TAG_PREFIX_ONLY:
        XdfBuildPrefixOnly(&rng, Case);
        break;
    case XDF_TAG_OPCODE38:
        if (XdfRngRange(&rng, 2) == 0)
        {
            XdfBuildOpcode38(&rng, Case);
        }
        else
        {
            XdfBuildTwoByte0F(&rng, Case);
        }
        break;
    case XDF_TAG_REX2:
        XdfBuildRex2(&rng, Case);
        break;
    case XDF_TAG_LEGACY:
    default:
        XdfBuildLegacy(&rng, Case);
        break;
    }

    // Never hand more than the architectural maximum to the decoder.
    if (Case->Len > XDF_MAX_LEN)
    {
        Case->Len = XDF_MAX_LEN;
    }
}


NDSTATUS
XdfDecodeEx(
    const XDF_CASE *Case,
    unsigned int Size,
    unsigned int Options,
    unsigned int VendMode,
    unsigned int FeatMode,
    INSTRUX *Instrux
)
{
    ND_CONTEXT context;

    NdInitContext(&context);

    context.DefCode = Case->DefCode;
    context.DefData = Case->DefCode;
    context.DefStack = Case->DefCode;
    context.VendMode = VendMode;
    context.FeatMode = FeatMode;
    context.Options = Options;

    return NdDecodeWithContext(Instrux, Case->Bytes, Size, &context);
}


NDSTATUS
XdfDecode(
    const XDF_CASE *Case,
    unsigned int Size,
    INSTRUX *Instrux
)
{
    return XdfDecodeEx(Case, Size, 0, ND_VEND_ANY, ND_FEAT_ALL, Instrux);
}
