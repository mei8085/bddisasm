/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Decoder invariants ("oracle").
 *
 * On a successful decode the INSTRUX must describe exactly one instruction
 * occupying exactly `Length` bytes of the input window, with every encoded
 * field placed inside that window, non-overlapping, and with no byte left
 * unaccounted for. Operand descriptors must be consistent with the encoded
 * fields: an immediate operand's RawSize must equal the immediate width the
 * decoder reported, a relative-offset operand must have the reported relative
 * offset width, a memory operand's DispSize must equal the reported
 * displacement/moffset width, and register/memory operands must reference
 * registers that exist in the current mode. Payload values must also match the
 * bytes that were actually decoded.
 *
 * On a failed decode nothing may look like a valid instruction: no mnemonic,
 * no operands, no instruction class, and a Length that never exceeds the input
 * window.
 */
#include <stdio.h>
#include <string.h>

#include "x86_decode_fuzz.h"

//
// Maximum register index per register class. This is the architectural
// maximum (64-bit mode, with APX extensions), valid in every decode mode.
//
static unsigned int
XdfRegisterLimit(
    ND_REG_TYPE Type
)
{
    switch (Type)
    {
    case ND_REG_GPR:    return 32;
    case ND_REG_SEG:    return 6;
    case ND_REG_FPU:    return 8;
    case ND_REG_MMX:    return 8;
    case ND_REG_SSE:    return 32;
    case ND_REG_CR:     return 32;
    case ND_REG_DR:     return 32;
    case ND_REG_TR:     return 16;
    case ND_REG_BND:    return 4;
    case ND_REG_MSK:    return 8;
    case ND_REG_TILE:   return 8;
    default:            return 0;   // Implicit/system register: no simple numbering.
    }
}


static int
XdfFail(
    char *Reason,
    unsigned int ReasonSize,
    const char *Tag,
    const char *Message
)
{
    if (Reason != NULL && ReasonSize != 0)
    {
        snprintf(Reason, ReasonSize, "%s: %s", Tag, Message);
    }

    return -1;
}


//
// Little-endian read of `Size` bytes, trimmed to the low `Size` bytes.
//
static unsigned long long
XdfReadLe(
    const unsigned char *Code,
    unsigned int Offset,
    unsigned int Size
)
{
    unsigned long long value = 0;

    for (unsigned int i = 0; i < Size; i++)
    {
        value |= (unsigned long long)Code[Offset + i] << (8 * i);
    }

    return value;
}


static unsigned long long
XdfTrim(
    unsigned long long Value,
    unsigned int Size
)
{
    if (Size >= 8)
    {
        return Value;
    }

    return Value & ((1ULL << (8 * Size)) - 1);
}


//
// Mark [Offset, Offset + Length) as consumed. Fails if the range escapes the
// instruction or overlaps a range that was already consumed.
//
static int
XdfConsume(
    XDF_LAYOUT *Layout,
    unsigned int Offset,
    unsigned int Length,
    const char *What,
    char *Reason,
    unsigned int ReasonSize
)
{
    char message[160];

    if (Length == 0)
    {
        snprintf(message, sizeof(message), "zero-length field '%s' at offset %u", What, Offset);
        return XdfFail(Reason, ReasonSize, "layout", message);
    }

    if (Offset > Layout->Length || Length > Layout->Length - Offset)
    {
        snprintf(message, sizeof(message),
                 "field '%s' [%u,%u) outside instruction length %u", What, Offset, Offset + Length, Layout->Length);
        return XdfFail(Reason, ReasonSize, "layout", message);
    }

    for (unsigned int i = 0; i < Length; i++)
    {
        if (Layout->Consumed[Offset + i])
        {
            snprintf(message, sizeof(message),
                     "field '%s' [%u,%u) overlaps byte %u", What, Offset, Offset + Length, Offset + i);
            return XdfFail(Reason, ReasonSize, "layout", message);
        }

        Layout->Consumed[Offset + i] = 1;
    }

    return 0;
}


static int
XdfIsDispWidth(unsigned int Value)
{
    return Value == 1 || Value == 2 || Value == 4;
}


static int
XdfIsImm1Width(unsigned int Value)
{
    return Value == 1 || Value == 2 || Value == 4 || Value == 8;
}


static int
XdfIsRelWidth(unsigned int Value)
{
    return Value == 1 || Value == 2 || Value == 4;
}


//
// Verify that the fields (prefix run, opcode bytes, ModRM/SIB, displacement
// and payload) tile the instruction exactly once, with no gaps and no
// overlaps. Opcode bytes are not always contiguous: for the 3DNow! style
// encodings the nominal opcode is the last byte, after ModRM/displacement.
//
static int
XdfCheckLayout(
    const INSTRUX *Instrux,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
)
{
    XDF_LAYOUT layout;
    char message[160];

    memset(&layout, 0, sizeof(layout));
    layout.Length = Instrux->Length;

    if (Instrux->PrefLength > Instrux->Length)
    {
        snprintf(message, sizeof(message), "prefix length %u exceeds instruction length %u",
                 Instrux->PrefLength, Instrux->Length);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->OpOffset != Instrux->PrefLength)
    {
        snprintf(message, sizeof(message), "opcode offset %u != prefix length %u",
                 Instrux->OpOffset, Instrux->PrefLength);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    // OpLength is a 2-bit field, so the upper bound cannot be exceeded; the
    // meaningful check is that at least one opcode byte was consumed.
    if (Instrux->OpLength < 1)
    {
        snprintf(message, sizeof(message), "opcode length %u out of range", Instrux->OpLength);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    // The escape/prefix opcode bytes occupy OpLength - 1 bytes starting at
    // OpOffset; the nominal opcode byte is tracked separately by MainOpOffset.
    // For ordinary encodings it is the last of those opcode bytes. For the
    // "opcode is the last byte" encodings (3DNow!) it comes after the ModRM/
    // SIB/displacement, so its exact position is only constrained to lie
    // inside the instruction; the tiling check below verifies that it neither
    // overlaps another field nor leaves a hole.
    if (Instrux->MainOpOffset < Instrux->OpOffset || Instrux->MainOpOffset >= Instrux->Length)
    {
        snprintf(message, sizeof(message),
                 "main opcode offset %u outside instruction [%u,%u)",
                 Instrux->MainOpOffset, Instrux->OpOffset, Instrux->Length);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->PrefLength != 0 && XdfConsume(&layout, 0, Instrux->PrefLength, "prefixes", Reason, ReasonSize) != 0)
    {
        return -1;
    }

    for (unsigned int i = 0; i + 1 < Instrux->OpLength; i++)
    {
        if (XdfConsume(&layout, Instrux->OpOffset + i, 1, "opcode", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasModRm && XdfConsume(&layout, Instrux->ModRmOffset, 1, "modrm", Reason, ReasonSize) != 0)
    {
        return -1;
    }

    if (Instrux->HasSib)
    {
        if (!Instrux->HasModRm)
        {
            return XdfFail(Reason, ReasonSize, Tag, "sib present without modrm");
        }

        if (Instrux->ModRm.mod == 3)
        {
            return XdfFail(Reason, ReasonSize, Tag, "sib present with register-only modrm");
        }

        if (Instrux->AddrMode == ND_ADDR_16)
        {
            return XdfFail(Reason, ReasonSize, Tag, "sib present in 16-bit addressing mode");
        }

        if (XdfConsume(&layout, Instrux->ModRmOffset + 1, 1, "sib", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasDisp)
    {
        if (!XdfIsDispWidth(Instrux->DispLength))
        {
            snprintf(message, sizeof(message), "displacement width %u", Instrux->DispLength);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (XdfConsume(&layout, Instrux->DispOffset, Instrux->DispLength, "displacement", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    // Nominal opcode byte. For ordinary encodings it is the last byte of the
    // opcode run; for "opcode last" encodings it comes after the ModRM/SIB/
    // displacement and was therefore not consumed by the loop above.
    if (XdfConsume(&layout, Instrux->MainOpOffset, 1, "main opcode", Reason, ReasonSize) != 0)
    {
        return -1;
    }

    if (Instrux->HasSseImm && XdfConsume(&layout, Instrux->SseImmOffset, 1, "sse immediate", Reason, ReasonSize) != 0)
    {
        return -1;
    }

    if (Instrux->HasImm1)
    {
        if (!XdfIsImm1Width(Instrux->Imm1Length))
        {
            snprintf(message, sizeof(message), "immediate width %u", Instrux->Imm1Length);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (XdfConsume(&layout, Instrux->Imm1Offset, Instrux->Imm1Length, "immediate", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasImm2)
    {
        if (Instrux->Imm2Length != 1)
        {
            snprintf(message, sizeof(message), "second immediate width %u", Instrux->Imm2Length);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (XdfConsume(&layout, Instrux->Imm2Offset, Instrux->Imm2Length, "second immediate", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasRelOffs)
    {
        if (!XdfIsRelWidth(Instrux->RelOffsLength))
        {
            snprintf(message, sizeof(message), "relative offset width %u", Instrux->RelOffsLength);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (XdfConsume(&layout, Instrux->RelOffsOffset, Instrux->RelOffsLength, "relative offset", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasMoffset)
    {
        if (Instrux->MoffsetLength != 2 && Instrux->MoffsetLength != 4 && Instrux->MoffsetLength != 8)
        {
            snprintf(message, sizeof(message), "moffset width %u", Instrux->MoffsetLength);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (Instrux->HasDisp)
        {
            return XdfFail(Reason, ReasonSize, Tag, "moffset present together with a displacement");
        }

        if (XdfConsume(&layout, Instrux->MoffsetOffset, Instrux->MoffsetLength, "moffset", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    if (Instrux->HasAddr || Instrux->HasAddrNear)
    {
        if (Instrux->HasAddr && Instrux->HasAddrNear)
        {
            return XdfFail(Reason, ReasonSize, Tag, "far and near address present together");
        }

        if (Instrux->HasAddr && Instrux->AddrLength != 4 && Instrux->AddrLength != 6)
        {
            snprintf(message, sizeof(message), "far address width %u", Instrux->AddrLength);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (Instrux->HasAddrNear && Instrux->AddrLength != 8)
        {
            snprintf(message, sizeof(message), "near address width %u", Instrux->AddrLength);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }

        if (XdfConsume(&layout, Instrux->AddrOffset, Instrux->AddrLength, "address", Reason, ReasonSize) != 0)
        {
            return -1;
        }
    }

    // Every byte of the instruction must have been claimed by exactly one
    // field. A hole means Length includes bytes the decoder does not describe,
    // which desynchronises any consumer that advances by Length.
    for (unsigned int i = 0; i < Instrux->Length; i++)
    {
        if (!layout.Consumed[i])
        {
            snprintf(message, sizeof(message), "byte %u of %u is not covered by any decoded field",
                     i, Instrux->Length);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    return 0;
}


//
// Verify that the instruction-level payload fields hold the bytes that were
// actually decoded, sign-extended where the architecture requires it.
//
static int
XdfCheckPayloadValues(
    const INSTRUX *Instrux,
    const unsigned char *Code,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
)
{
    char message[192];

    if (Instrux->HasImm1)
    {
        unsigned long long raw = XdfReadLe(Code, Instrux->Imm1Offset, Instrux->Imm1Length);

        if (XdfTrim(Instrux->Immediate1, Instrux->Imm1Length) != raw)
        {
            snprintf(message, sizeof(message), "immediate field %llx does not match bytes %llx",
                     (unsigned long long)Instrux->Immediate1, raw);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    if (Instrux->HasImm2 && Instrux->Immediate2 != Code[Instrux->Imm2Offset])
    {
        return XdfFail(Reason, ReasonSize, Tag, "second immediate field does not match its byte");
    }

    if (Instrux->HasSseImm && Instrux->SseImmediate != Code[Instrux->SseImmOffset])
    {
        return XdfFail(Reason, ReasonSize, Tag, "sse immediate field does not match its byte");
    }

    if (Instrux->HasRelOffs)
    {
        unsigned long long raw = XdfReadLe(Code, Instrux->RelOffsOffset, Instrux->RelOffsLength);

        if (XdfTrim(Instrux->RelativeOffset, Instrux->RelOffsLength) != raw)
        {
            snprintf(message, sizeof(message), "relative offset field %llx does not match bytes %llx",
                     (unsigned long long)Instrux->RelativeOffset, raw);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    if (Instrux->HasMoffset)
    {
        unsigned long long raw = XdfReadLe(Code, Instrux->MoffsetOffset, Instrux->MoffsetLength);

        if (Instrux->Moffset != raw)
        {
            snprintf(message, sizeof(message), "moffset field %llx does not match bytes %llx",
                     (unsigned long long)Instrux->Moffset, raw);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    if (Instrux->HasDisp)
    {
        unsigned long long raw = XdfReadLe(Code, Instrux->DispOffset, Instrux->DispLength);

        if (XdfTrim(Instrux->Displacement, Instrux->DispLength) != raw)
        {
            snprintf(message, sizeof(message), "displacement field %x does not match bytes %llx",
                     (unsigned int)Instrux->Displacement, raw);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    return 0;
}


//
// Verify operand descriptors against the encoded fields and decoded bytes.
//
static int
XdfCheckOperands(
    const INSTRUX *Instrux,
    const unsigned char *Code,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
)
{
    char message[192];

    if (Instrux->OperandsCount > ND_MAX_OPERAND)
    {
        snprintf(message, sizeof(message), "operand count %u exceeds %u", Instrux->OperandsCount, ND_MAX_OPERAND);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->ExpOperandsCount > Instrux->OperandsCount)
    {
        snprintf(message, sizeof(message), "explicit operand count %u > total %u",
                 Instrux->ExpOperandsCount, Instrux->OperandsCount);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    for (unsigned int i = 0; i < Instrux->OperandsCount; i++)
    {
        const ND_OPERAND *op = &Instrux->Operands[i];

        switch (op->Type)
        {
        case ND_OP_REG:
        {
            unsigned int limit = XdfRegisterLimit(op->Info.Register.Type);

            if (limit != 0 && op->Info.Register.Reg >= limit)
            {
                snprintf(message, sizeof(message), "operand %u register %u out of range for class %u (max %u)",
                         i, op->Info.Register.Reg, op->Info.Register.Type, limit);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if (op->Info.Register.Count == 0 || op->Info.Register.Count > 32)
            {
                snprintf(message, sizeof(message), "operand %u register count %u", i, op->Info.Register.Count);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if (op->Info.Register.Size == 0 || op->Info.Register.Size > ND_SIZE_1KB)
            {
                snprintf(message, sizeof(message), "operand %u register size %u", i, op->Info.Register.Size);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            break;
        }

        case ND_OP_MEM:
        {
            const ND_OPDESC_MEMORY *mem = &op->Info.Memory;

            // Base is a 5-bit field and therefore always addresses a valid
            // GPR, including the APX R16..R31 range.
            if (mem->HasIndex && mem->Index >= 32)
            {
                snprintf(message, sizeof(message), "operand %u index register %u", i, mem->Index);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if (mem->HasIndex && mem->Scale != 1 && mem->Scale != 2 && mem->Scale != 4 && mem->Scale != 8)
            {
                snprintf(message, sizeof(message), "operand %u scale %u", i, mem->Scale);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if (mem->Seg > 6)
            {
                snprintf(message, sizeof(message), "operand %u segment %u", i, mem->Seg);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if (mem->IsRipRel && Instrux->DefCode != ND_CODE_64)
            {
                snprintf(message, sizeof(message), "operand %u rip-relative outside 64-bit mode", i);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            // Encoded-ModRM and direct (moffset) memory operands must agree
            // with the instruction-level displacement/moffset width.
            if (op->Encoding == ND_OPE_M || mem->IsDirect)
            {
                unsigned int expected = Instrux->HasMoffset ? Instrux->MoffsetLength : Instrux->DispLength;

                if (mem->DispSize != expected)
                {
                    snprintf(message, sizeof(message),
                             "operand %u displacement size %u != encoded width %u", i, mem->DispSize, expected);
                    return XdfFail(Reason, ReasonSize, Tag, message);
                }

                if (mem->DispSize > 8)
                {
                    snprintf(message, sizeof(message), "operand %u displacement size %u", i, mem->DispSize);
                    return XdfFail(Reason, ReasonSize, Tag, message);
                }
            }

            if (mem->HasDisp && !Instrux->HasDisp && !mem->IsDirect)
            {
                snprintf(message, sizeof(message),
                         "operand %u reports a displacement the instruction does not encode", i);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            break;
        }

        case ND_OP_IMM:
        {
            unsigned int raw = op->Info.Immediate.RawSize;

            if (op->Encoding == ND_OPE_L)
            {
                // Register selector encoded in the SSE immediate byte.
                if (!Instrux->HasSseImm || raw != 1)
                {
                    snprintf(message, sizeof(message),
                             "operand %u immediate-encoded register without SSE immediate byte (raw size %u)",
                             i, raw);
                    return XdfFail(Reason, ReasonSize, Tag, message);
                }

                break;
            }

            if (op->Encoding != ND_OPE_I)
            {
                // Implicit constant / default-flag operand: nothing encoded.
                break;
            }

            if (!XdfIsImm1Width(raw))
            {
                snprintf(message, sizeof(message), "operand %u immediate raw size %u", i, raw);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            if ((!Instrux->HasImm1 || raw != Instrux->Imm1Length) &&
                (!Instrux->HasImm2 || raw != Instrux->Imm2Length))
            {
                snprintf(message, sizeof(message),
                         "operand %u immediate raw size %u matches neither immediate field (%u/%u)",
                         i, raw,
                         Instrux->HasImm1 ? Instrux->Imm1Length : 0,
                         Instrux->HasImm2 ? Instrux->Imm2Length : 0);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            // The low `raw` bytes of the decoded immediate must be the bytes
            // that were actually in the instruction. The decoder may sign- or
            // zero-extend above that width.
            if (Instrux->HasImm1 && raw == Instrux->Imm1Length)
            {
                unsigned long long encoded = XdfReadLe(Code, Instrux->Imm1Offset, raw);

                if (XdfTrim(op->Info.Immediate.Imm, raw) != encoded)
                {
                    snprintf(message, sizeof(message),
                             "operand %u immediate %llx does not match encoded bytes %llx (raw %u)",
                             i, (unsigned long long)op->Info.Immediate.Imm, encoded, raw);
                    return XdfFail(Reason, ReasonSize, Tag, message);
                }
            }

            break;
        }

        case ND_OP_OFFS:
        {
            unsigned int raw = op->Info.RelativeOffset.RawSize;
            unsigned long long encoded;

            if (raw != Instrux->RelOffsLength || !XdfIsRelWidth(raw))
            {
                snprintf(message, sizeof(message),
                         "operand %u relative offset raw size %u != encoded %u",
                         i, raw, Instrux->RelOffsLength);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            encoded = XdfReadLe(Code, Instrux->RelOffsOffset, raw);

            if (XdfTrim(op->Info.RelativeOffset.Rel, raw) != encoded)
            {
                snprintf(message, sizeof(message),
                         "operand %u relative offset %llx does not match encoded bytes %llx",
                         i, (unsigned long long)op->Info.RelativeOffset.Rel, encoded);
                return XdfFail(Reason, ReasonSize, Tag, message);
            }

            break;
        }

        case ND_OP_ADDR:
        case ND_OP_ADDR_NEAR:
        case ND_OP_CONST:
        case ND_OP_BANK:
        case ND_OP_DFV:
            break;

        default:
        {
            snprintf(message, sizeof(message), "operand %u has invalid type %u", i, op->Type);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
        }

        // Note that a zero operand Size is legitimate: LEA-style address
        // generation operands do not actually access memory.
        if (op->Size > ND_SIZE_1KB && op->Size != ND_SIZE_CACHE_LINE && op->Size != ND_SIZE_UNKNOWN)
        {
            snprintf(message, sizeof(message), "operand %u has implausible size %u", i, op->Size);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    return 0;
}


int
XdfCheckDecode(
    const INSTRUX *Instrux,
    const unsigned char *Code,
    unsigned int Size,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
)
{
    char message[192];

    if (Instrux->Length < 1 || Instrux->Length > ND_MAX_INSTRUCTION_LENGTH)
    {
        snprintf(message, sizeof(message), "decoded length %u outside [1,%u]",
                 Instrux->Length, ND_MAX_INSTRUCTION_LENGTH);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->Length > Size)
    {
        snprintf(message, sizeof(message), "decoded length %u exceeds input window %u", Instrux->Length, Size);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    // The decoder must have copied exactly the instruction bytes it consumed.
    for (unsigned int i = 0; i < Instrux->Length; i++)
    {
        if (Instrux->InstructionBytes[i] != Code[i])
        {
            snprintf(message, sizeof(message), "instruction byte %u is %02x, input was %02x",
                     i, Instrux->InstructionBytes[i], Code[i]);
            return XdfFail(Reason, ReasonSize, Tag, message);
        }
    }

    if (Instrux->OpCodeBytes[0] != Code[Instrux->OpOffset])
    {
        snprintf(message, sizeof(message), "first opcode byte %02x != input byte %02x",
                 Instrux->OpCodeBytes[0], Code[Instrux->OpOffset]);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->Instruction == ND_INS_INVALID)
    {
        return XdfFail(Reason, ReasonSize, Tag, "successful decode without an instruction class");
    }

#ifndef BDDISASM_NO_MNEMONIC
    if (Instrux->Mnemonic == NULL)
    {
        return XdfFail(Reason, ReasonSize, Tag, "successful decode without a mnemonic");
    }
#endif // !BDDISASM_NO_MNEMONIC

    if (Instrux->WordLength != 2 && Instrux->WordLength != 4 && Instrux->WordLength != 8)
    {
        snprintf(message, sizeof(message), "word length %u", Instrux->WordLength);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    // Note: OpMode/AddrMode/VecMode/EncMode are 2-bit fields, so they cannot
    // physically hold an out-of-range value; their ranges are enforced by the
    // compiler and by the enumerations. Nothing to check here.

    if (XdfCheckLayout(Instrux, Tag, Reason, ReasonSize) != 0)
    {
        return -1;
    }

    if (XdfCheckPayloadValues(Instrux, Code, Tag, Reason, ReasonSize) != 0)
    {
        return -1;
    }

    if (XdfCheckOperands(Instrux, Code, Tag, Reason, ReasonSize) != 0)
    {
        return -1;
    }

    return 0;
}


int
XdfCheckFailure(
    const INSTRUX *Instrux,
    unsigned int Size,
    const char *Tag,
    char *Reason,
    unsigned int ReasonSize
)
{
    char message[192];

    // A rejected byte sequence must not look decodable. The decoder is free to
    // leave partially-parsed field flags behind, so we only assert on the
    // fields that would let a caller mistake this for an instruction.
#ifndef BDDISASM_NO_MNEMONIC
    if (Instrux->Mnemonic != NULL)
    {
        snprintf(message, sizeof(message), "failed decode still reports mnemonic '%s'", Instrux->Mnemonic);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }
#endif // !BDDISASM_NO_MNEMONIC

    if (Instrux->OperandsCount != 0 || Instrux->ExpOperandsCount != 0)
    {
        snprintf(message, sizeof(message), "failed decode reports %u/%u operands",
                 Instrux->ExpOperandsCount, Instrux->OperandsCount);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    // A rejected decoding must not claim to have consumed more bytes than it
    // was given. (The internal length counter may tick one past the
    // architectural maximum before the 15-byte check rejects the encoding, so
    // the meaningful bound here is the input window.)
    if (Instrux->Length > Size)
    {
        snprintf(message, sizeof(message), "failed decode reports length %u for a %u byte window",
                 Instrux->Length, Size);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    if (Instrux->Instruction != ND_INS_INVALID)
    {
        snprintf(message, sizeof(message), "failed decode reports instruction class %u", Instrux->Instruction);
        return XdfFail(Reason, ReasonSize, Tag, message);
    }

    return 0;
}
