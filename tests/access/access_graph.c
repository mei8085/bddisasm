/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "access_graph.h"

static const char *gGprNames[ND_MAX_GPR_REGS] =
{
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
};

static const char *gSegNames[ND_MAX_SEG_REGS] =
{
    "es", "cs", "ss", "ds", "fs", "gs", "inv6", "inv7",
};

static const char *gCrNames[ND_MAX_CR_REGS] =
{
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
    "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15",
    "cr16", "cr17", "cr18", "cr19", "cr20", "cr21", "cr22", "cr23",
    "cr24", "cr25", "cr26", "cr27", "cr28", "cr29", "cr30", "cr31",
};

static const char *gDrNames[ND_MAX_DR_REGS] =
{
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
    "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15",
    "dr16", "dr17", "dr18", "dr19", "dr20", "dr21", "dr22", "dr23",
    "dr24", "dr25", "dr26", "dr27", "dr28", "dr29", "dr30", "dr31",
};

static const char *gSysNames[ND_MAX_SYS_REGS] =
{
    "gdtr", "idtr", "ldtr", "tr", "sys4", "sys5", "sys6", "sys7",
};

static const char *gX87Names[ND_MAX_X87_REGS] =
{
    "x87control", "x87tag", "x87status", "x87_3", "x87_4", "x87_5", "x87_6", "x87_7",
};

static uint8_t
AgFromAccess(
    ND_OPERAND_ACCESS Access
)
{
    uint8_t acc = AG_NONE;

    if (Access.Read) acc |= AG_READ;
    if (Access.Write) acc |= AG_WRITE;
    if (Access.CondRead) acc |= AG_COND_READ;
    if (Access.CondWrite) acc |= AG_COND_WRITE;
    if (Access.Prefetch) acc |= AG_PREFETCH;

    return acc;
}

//
// Add the addressing registers of a memory operand to the graph. Address generation operands
// (LEA) contribute reads for base/index/segment but no memory access, which is exactly what the
// consumer of the graph needs: these registers must never be reported as modified.
//
static void
AgAddAddressing(
    const ND_OPDESC_MEMORY *Mem,
    AG_GRAPH *Graph
)
{
    // RIP-relative addressing does not read a tracked register: RIP is not part of the data-flow
    // register file, and NdGetFullAccessMap reports no RIP access for it either. Only control
    // transfers (branches, calls, returns) touch the RIP slot. The segment is still used.
    if (Mem->IsRipRel)
    {
        if (Mem->HasSeg)
        {
            Graph->Seg[Mem->Seg] |= AG_READ;
        }
        return;
    }

    if (Mem->HasSeg)
    {
        Graph->Seg[Mem->Seg] |= AG_READ;
    }

    if (Mem->HasBase)
    {
        Graph->Gpr[Mem->Base] |= AG_READ;
    }

    if (Mem->HasIndex)
    {
        if (Mem->IsVsib)
        {
            if (Mem->Index < ND_MAX_SSE_REGS)
            {
                Graph->Sse[Mem->Index] |= AG_READ;
            }
        }
        else
        {
            Graph->Gpr[Mem->Index] |= AG_READ;
        }
    }
}

void
AgBuildOperandView(
    const INSTRUX *Instrux,
    AG_GRAPH *Graph
)
{
    unsigned i;

    memset(Graph, 0, sizeof(*Graph));

    Graph->StackWords = Instrux->StackWords;

    Graph->FlagsTested = Instrux->FlagsAccess.Tested.Raw;
    Graph->FlagsModified = Instrux->FlagsAccess.Modified.Raw;
    Graph->FlagsSet = Instrux->FlagsAccess.Set.Raw;
    Graph->FlagsCleared = Instrux->FlagsAccess.Cleared.Raw;
    Graph->FlagsUndefined = Instrux->FlagsAccess.Undefined.Raw;

    for (i = 0; i < Instrux->OperandsCount; i++)
    {
        const ND_OPERAND *op = &Instrux->Operands[i];
        uint8_t acc = AgFromAccess(op->Access);
        unsigned k, count;

        switch (op->Type)
        {
        case ND_OP_MEM:
            if (op->Info.Memory.IsStack)
            {
                // Any stack access reads and updates the stack pointer and uses SS.
                Graph->Stack |= acc;
                Graph->Gpr[NDR_RSP] |= AG_READ | AG_WRITE;
                Graph->Seg[NDR_SS] |= AG_READ;
            }
            else
            {
                if (op->Info.Memory.IsShadowStack)
                {
                    Graph->ShadowMem |= acc;
                }
                else
                {
                    Graph->Mem |= acc;
                }

                AgAddAddressing(&op->Info.Memory, Graph);
            }
            break;

        case ND_OP_REG:
            {
                const ND_OPDESC_REGISTER *reg = &op->Info.Register;

                count = reg->Count ? reg->Count : 1;

                switch (reg->Type)
                {
                case ND_REG_GPR:
                    for (k = 0; k < count; k++)
                    {
                        unsigned id = reg->IsHigh8 ? (reg->Reg - 4) : (reg->Reg + k);
                        if (id < ND_MAX_GPR_REGS)
                        {
                            Graph->Gpr[id] |= acc;
                        }
                    }
                    break;
                case ND_REG_SEG:
                    if (NDR_CS == reg->Reg)
                    {
                        // CS is represented by its own aggregate, not by the segment bank.
                        Graph->Cs |= acc;
                    }
                    else if (reg->Reg < ND_MAX_SEG_REGS)
                    {
                        Graph->Seg[reg->Reg] |= acc;
                    }
                    break;
                case ND_REG_FPU:
                    if (reg->Reg < ND_MAX_FPU_REGS)
                    {
                        Graph->Fpu[reg->Reg] |= acc;
                    }
                    break;
                case ND_REG_MMX:
                    if (reg->Reg < ND_MAX_MMX_REGS)
                    {
                        Graph->Mmx[reg->Reg] |= acc;
                    }
                    break;
                case ND_REG_SSE:
                    for (k = 0; k < count; k++)
                    {
                        if (reg->Reg + k < ND_MAX_SSE_REGS)
                        {
                            Graph->Sse[reg->Reg + k] |= acc;
                        }
                    }
                    break;
                case ND_REG_CR:
                    if (reg->Reg < ND_MAX_CR_REGS) Graph->Cr[reg->Reg] |= acc;
                    break;
                case ND_REG_DR:
                    if (reg->Reg < ND_MAX_DR_REGS) Graph->Dr[reg->Reg] |= acc;
                    break;
                case ND_REG_TR:
                    if (reg->Reg < ND_MAX_TR_REGS) Graph->Tr[reg->Reg] |= acc;
                    break;
                case ND_REG_BND:
                    if (reg->Reg < ND_MAX_BND_REGS) Graph->Bnd[reg->Reg] |= acc;
                    break;
                case ND_REG_MSK:
                    if (reg->Reg < ND_MAX_MSK_REGS) Graph->Msk[reg->Reg] |= acc;
                    break;
                case ND_REG_TILE:
                    for (k = 0; k < count; k++)
                    {
                        if (reg->Reg + k < ND_MAX_TILE_REGS) Graph->Tmm[reg->Reg + k] |= acc;
                    }
                    break;
                case ND_REG_SYS:
                    // Reported verbatim. Note that the x87 control/tag/status words share these
                    // ids with GDTR/IDTR/LDTR; that ambiguity is surfaced by the sweep's
                    // "sys-slot-aliasing" invariant instead of being papered over here.
                    if (reg->Reg < ND_MAX_SYS_REGS) Graph->Sys[reg->Reg] |= acc;
                    break;
                case ND_REG_X87:
                    if (reg->Reg < ND_MAX_X87_REGS) Graph->X87[reg->Reg] |= acc;
                    break;
                case ND_REG_FLG:
                    Graph->Flags |= acc;
                    break;
                case ND_REG_RIP:
                    Graph->Rip |= acc;
                    break;
                case ND_REG_MXCSR:
                    Graph->Mxcsr |= acc;
                    break;
                case ND_REG_PKRU:
                    Graph->Pkru |= acc;
                    break;
                case ND_REG_SSP:
                    Graph->Ssp |= acc;
                    break;
                case ND_REG_UIF:
                    Graph->Uif |= acc;
                    break;
                default:
                    break;
                }
            }
            break;

        case ND_OP_BANK:
            // A bank operand carries no register identity; the concrete registers must be
            // described by the explicit/implicit register operands that accompany it. Whether a
            // bank resolves to any state is checked by the sweep, which looks for register
            // accesses in the map that no operand accounts for.
            break;

        default:
            break;
        }
    }
}

NDSTATUS
AgBuildMapView(
    const INSTRUX *Instrux,
    AG_GRAPH *Graph
)
{
    ND_ACCESS_MAP map;
    NDSTATUS status;

    memset(Graph, 0, sizeof(*Graph));
    memset(&map, 0, sizeof(map));

    status = NdGetFullAccessMap(Instrux, &map);
    if (status != ND_STATUS_SUCCESS)
    {
        return status;
    }

    Graph->Mem = map.MemAccess;
    Graph->Stack = map.StackAccess;
    Graph->Flags = map.FlagsAccess;
    Graph->Rip = map.RipAccess;
    Graph->Ssp = map.SspAccess;
    Graph->Mxcsr = map.MxcsrAccess;
    Graph->Pkru = map.PkruAccess;
    Graph->StackWords = Instrux->StackWords;

    Graph->FlagsTested = Instrux->FlagsAccess.Tested.Raw;
    Graph->FlagsModified = Instrux->FlagsAccess.Modified.Raw;
    Graph->FlagsSet = Instrux->FlagsAccess.Set.Raw;
    Graph->FlagsCleared = Instrux->FlagsAccess.Cleared.Raw;
    Graph->FlagsUndefined = Instrux->FlagsAccess.Undefined.Raw;

    memcpy(Graph->Gpr, map.GprAccess, sizeof(Graph->Gpr));
    memcpy(Graph->Seg, map.SegAccess, sizeof(Graph->Seg));
    Graph->Seg[NDR_CS] = 0;
    memcpy(Graph->Fpu, map.FpuAccess, sizeof(Graph->Fpu));
    memcpy(Graph->Mmx, map.MmxAccess, sizeof(Graph->Mmx));
    memcpy(Graph->Sse, map.SseAccess, sizeof(Graph->Sse));
    memcpy(Graph->Cr, map.CrAccess, sizeof(Graph->Cr));
    memcpy(Graph->Dr, map.DrAccess, sizeof(Graph->Dr));
    memcpy(Graph->Tr, map.TrAccess, sizeof(Graph->Tr));
    memcpy(Graph->Bnd, map.BndAccess, sizeof(Graph->Bnd));
    memcpy(Graph->Msk, map.MskAccess, sizeof(Graph->Msk));
    memcpy(Graph->Tmm, map.TmmAccess, sizeof(Graph->Tmm));
    memcpy(Graph->Sys, map.SysAccess, sizeof(Graph->Sys));
    memcpy(Graph->X87, map.X87Access, sizeof(Graph->X87));

    // CS has a dedicated aggregate in INSTRUX; keep it out of the segment bank so the two views
    // line up.
    Graph->Cs = Instrux->CsAccess;

    return ND_STATUS_SUCCESS;
}

//
// Access string formatting/parsing.
//
static void
AgAccessToString(
    uint8_t Access,
    char *Buffer
)
{
    int pos = 0;

    if (Access == AG_NONE)
    {
        strcpy(Buffer, "-");
        return;
    }

    if (Access & AG_READ) strcpy(Buffer + pos, "R"), pos += 1;
    if (Access & AG_WRITE) strcpy(Buffer + pos, "W"), pos += 1;
    if (Access & AG_COND_READ) strcpy(Buffer + pos, "CR"), pos += 2;
    if (Access & AG_COND_WRITE) strcpy(Buffer + pos, "CW"), pos += 2;
    if (Access & AG_PREFETCH) strcpy(Buffer + pos, "P"), pos += 1;

    Buffer[pos] = 0;
}

static int
AgAccessFromString(
    const char *Text
)
{
    int acc = 0;
    const char *p = Text;

    if (0 == strcmp(Text, "-") || 0 == strcmp(Text, "NONE"))
    {
        return AG_NONE;
    }

    while (*p)
    {
        if (0 == strncmp(p, "CR", 2)) { acc |= AG_COND_READ; p += 2; }
        else if (0 == strncmp(p, "CW", 2)) { acc |= AG_COND_WRITE; p += 2; }
        else if (*p == 'R') { acc |= AG_READ; p++; }
        else if (*p == 'W') { acc |= AG_WRITE; p++; }
        else if (*p == 'P') { acc |= AG_PREFETCH; p++; }
        else if (*p == '+' ) { p++; }
        else return -1;
    }

    return acc;
}

static void
AgAppendScalar(
    char *Buffer,
    size_t BufferSize,
    const char *Name,
    uint8_t Access
)
{
    char acc[16];
    size_t used = strlen(Buffer);

    if (0 == Access)
    {
        return;
    }

    AgAccessToString(Access, acc);
    snprintf(Buffer + used, BufferSize - used, "%s%s=%s", used ? ";" : "", Name, acc);
}

static void
AgAppendFlagDetail(
    char *Buffer,
    size_t BufferSize,
    const char *Name,
    uint32_t Value
)
{
    size_t used;

    if (0 == Value)
    {
        return;
    }

    used = strlen(Buffer);
    snprintf(Buffer + used, BufferSize - used, "%s%s=0x%x", used ? ";" : "", Name, Value);
}

static void
AgAppendNamedBank(
    char *Buffer,
    size_t BufferSize,
    const char *Label,
    const uint8_t *Bank,
    unsigned Count,
    const char *const *Names
)
{
    unsigned i;
    int first = 1;
    size_t used;

    for (i = 0; i < Count; i++)
    {
        if (0 == Bank[i])
        {
            continue;
        }

        used = strlen(Buffer);
        if (first)
        {
            snprintf(Buffer + used, BufferSize - used, "%s%s:", used ? ";" : "", Label);
            used = strlen(Buffer);
            first = 0;
        }
        else
        {
            snprintf(Buffer + used, BufferSize - used, ",");
            used = strlen(Buffer);
        }

        {
            char acc[16];
            AgAccessToString(Bank[i], acc);
            snprintf(Buffer + used, BufferSize - used, "%s=%s", Names[i], acc);
        }
    }
}

void
AgToString(
    const AG_GRAPH *Graph,
    char *Buffer,
    size_t BufferSize
)
{
    static const char *mmxNames[ND_MAX_MMX_REGS] =
        { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" };
    static const char *fpuNames[ND_MAX_FPU_REGS] =
        { "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7" };
    static const char *sseNames[ND_MAX_SSE_REGS] =
    {
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
        "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31",
    };
    static const char *trNames[ND_MAX_TR_REGS] =
    {
        "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
        "tr8", "tr9", "tr10", "tr11", "tr12", "tr13", "tr14", "tr15",
    };
    static const char *bndNames[ND_MAX_BND_REGS] = { "bnd0", "bnd1", "bnd2", "bnd3" };
    static const char *mskNames[ND_MAX_MSK_REGS] = { "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7" };
    static const char *tmmNames[ND_MAX_TILE_REGS] =
        { "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7" };
    static const char *x87Names[ND_MAX_X87_REGS] =
        { "x87_0", "x87_1", "x87_2", "x87_3", "x87_4", "x87_5", "x87_6", "x87_7" };

    Buffer[0] = 0;

    AgAppendScalar(Buffer, BufferSize, "mem", Graph->Mem);
    AgAppendScalar(Buffer, BufferSize, "shadow", Graph->ShadowMem);
    AgAppendScalar(Buffer, BufferSize, "stack", Graph->Stack);
    AgAppendScalar(Buffer, BufferSize, "rfl", Graph->Flags);
    AgAppendScalar(Buffer, BufferSize, "rip", Graph->Rip);
    AgAppendScalar(Buffer, BufferSize, "cs", Graph->Cs);
    AgAppendScalar(Buffer, BufferSize, "ssp", Graph->Ssp);
    AgAppendScalar(Buffer, BufferSize, "mxcsr", Graph->Mxcsr);
    AgAppendScalar(Buffer, BufferSize, "pkru", Graph->Pkru);
    AgAppendScalar(Buffer, BufferSize, "uif", Graph->Uif);

    if (Graph->StackWords)
    {
        size_t used = strlen(Buffer);
        snprintf(Buffer + used, BufferSize - used, "%ssw=%u", used ? ";" : "", Graph->StackWords);
    }

    AgAppendNamedBank(Buffer, BufferSize, "gpr", Graph->Gpr, ND_MAX_GPR_REGS,
                      (const char *const *)gGprNames);
    AgAppendNamedBank(Buffer, BufferSize, "seg", Graph->Seg, ND_MAX_SEG_REGS,
                      (const char *const *)gSegNames);
    AgAppendNamedBank(Buffer, BufferSize, "fpu", Graph->Fpu, ND_MAX_FPU_REGS,
                      (const char *const *)fpuNames);
    AgAppendNamedBank(Buffer, BufferSize, "mmx", Graph->Mmx, ND_MAX_MMX_REGS,
                      (const char *const *)mmxNames);
    AgAppendNamedBank(Buffer, BufferSize, "sse", Graph->Sse, ND_MAX_SSE_REGS,
                      (const char *const *)sseNames);
    AgAppendNamedBank(Buffer, BufferSize, "cr", Graph->Cr, ND_MAX_CR_REGS,
                      (const char *const *)gCrNames);
    AgAppendNamedBank(Buffer, BufferSize, "dr", Graph->Dr, ND_MAX_DR_REGS,
                      (const char *const *)gDrNames);
    AgAppendNamedBank(Buffer, BufferSize, "tr", Graph->Tr, ND_MAX_TR_REGS,
                      (const char *const *)trNames);
    AgAppendNamedBank(Buffer, BufferSize, "bnd", Graph->Bnd, ND_MAX_BND_REGS,
                      (const char *const *)bndNames);
    AgAppendNamedBank(Buffer, BufferSize, "msk", Graph->Msk, ND_MAX_MSK_REGS,
                      (const char *const *)mskNames);
    AgAppendNamedBank(Buffer, BufferSize, "tmm", Graph->Tmm, ND_MAX_TILE_REGS,
                      (const char *const *)tmmNames);
    AgAppendNamedBank(Buffer, BufferSize, "sys", Graph->Sys, ND_MAX_SYS_REGS, gSysNames);
    AgAppendNamedBank(Buffer, BufferSize, "x87", Graph->X87, ND_MAX_X87_REGS,
                      (const char *const *)x87Names);

    AgAppendFlagDetail(Buffer, BufferSize, "ft", Graph->FlagsTested);
    AgAppendFlagDetail(Buffer, BufferSize, "fm", Graph->FlagsModified);
    AgAppendFlagDetail(Buffer, BufferSize, "fs", Graph->FlagsSet);
    AgAppendFlagDetail(Buffer, BufferSize, "fc", Graph->FlagsCleared);
    AgAppendFlagDetail(Buffer, BufferSize, "fu", Graph->FlagsUndefined);
}

//
// Expectation parser.
//
static int
AgFindNamed(const char *Name, const char *const *Names, unsigned Count)
{
    unsigned i;

    for (i = 0; i < Count; i++)
    {
        if (0 == strcmp(Name, Names[i]))
        {
            return (int)i;
        }
    }

    return -1;
}

//
// Minimal re-entrant tokenizer. Kept local because strtok_r is POSIX, and this file is built as
// plain C11 by both the test runner and anyone reusing it.
//
static char *
AgNextToken(
    char *Cursor,
    char Delim,
    char **Next
)
{
    char *start;

    if (NULL == Cursor)
    {
        *Next = NULL;
        return NULL;
    }

    start = Cursor;

    while (*start == Delim)
    {
        start++;
    }

    if (0 == *start)
    {
        *Next = NULL;
        return NULL;
    }

    {
        char *end = strchr(start, Delim);

        if (NULL == end)
        {
            *Next = start + strlen(start);
        }
        else
        {
            *end = 0;
            *Next = end + 1;
        }
    }

    return start;
}

//
// Map "bank:register" names onto an index in the corresponding bank. Every bank's printable
// names live in exactly one place in this file, so the parser and the printer can never drift
// apart.
//
static int
AgRegisterIndex(
    const char *Bank,
    const char *Name
)
{
    static const char *mmxNames[ND_MAX_MMX_REGS] =
        { "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" };
    static const char *fpuNames[ND_MAX_FPU_REGS] =
        { "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7" };
    static const char *sseNames[ND_MAX_SSE_REGS] =
    {
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
        "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
        "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31",
    };
    static const char *trNames[ND_MAX_TR_REGS] =
    {
        "tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
        "tr8", "tr9", "tr10", "tr11", "tr12", "tr13", "tr14", "tr15",
    };
    static const char *bndNames[ND_MAX_BND_REGS] = { "bnd0", "bnd1", "bnd2", "bnd3" };
    static const char *mskNames[ND_MAX_MSK_REGS] = { "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7" };
    static const char *tmmNames[ND_MAX_TILE_REGS] =
        { "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7" };

    if (0 == strcmp(Bank, "gpr")) return AgFindNamed(Name, (const char *const *)gGprNames, ND_MAX_GPR_REGS);
    if (0 == strcmp(Bank, "seg")) return AgFindNamed(Name, (const char *const *)gSegNames, ND_MAX_SEG_REGS);
    if (0 == strcmp(Bank, "fpu")) return AgFindNamed(Name, (const char *const *)fpuNames, ND_MAX_FPU_REGS);
    if (0 == strcmp(Bank, "mmx")) return AgFindNamed(Name, (const char *const *)mmxNames, ND_MAX_MMX_REGS);
    if (0 == strcmp(Bank, "sse")) return AgFindNamed(Name, (const char *const *)sseNames, ND_MAX_SSE_REGS);
    if (0 == strcmp(Bank, "cr")) return AgFindNamed(Name, (const char *const *)gCrNames, ND_MAX_CR_REGS);
    if (0 == strcmp(Bank, "dr")) return AgFindNamed(Name, (const char *const *)gDrNames, ND_MAX_DR_REGS);
    if (0 == strcmp(Bank, "tr")) return AgFindNamed(Name, (const char *const *)trNames, ND_MAX_TR_REGS);
    if (0 == strcmp(Bank, "bnd")) return AgFindNamed(Name, (const char *const *)bndNames, ND_MAX_BND_REGS);
    if (0 == strcmp(Bank, "msk")) return AgFindNamed(Name, (const char *const *)mskNames, ND_MAX_MSK_REGS);
    if (0 == strcmp(Bank, "tmm")) return AgFindNamed(Name, (const char *const *)tmmNames, ND_MAX_TILE_REGS);
    if (0 == strcmp(Bank, "sys")) return AgFindNamed(Name, (const char *const *)gSysNames, ND_MAX_SYS_REGS);
    if (0 == strcmp(Bank, "x87")) return AgFindNamed(Name, (const char *const *)gX87Names, ND_MAX_X87_REGS);

    return -2;
}

int
AgParseExpected(
    const char *Text,
    AG_GRAPH *Graph,
    char *Err,
    size_t ErrSize
)
{
    char copy[2048];
    char *cursor;
    char *token;

    memset(Graph, 0, sizeof(*Graph));

    if (strlen(Text) >= sizeof(copy))
    {
        snprintf(Err, ErrSize, "expectation too long");
        return -1;
    }

    strcpy(copy, Text);

    cursor = copy;

    for (token = AgNextToken(cursor, ';', &cursor); token; token = AgNextToken(cursor, ';', &cursor))
    {
        char *eq;
        char *name;
        char *value;

        // Trim.
        while (*token == ' ' || *token == '\t') token++;

        if (0 == *token)
        {
            continue;
        }

        // A bank entry is "label:reg=acc,reg=acc", so the label separator comes before the first
        // access separator. A scalar entry is simply "field=acc".
        {
            char *colon = strchr(token, ':');

            eq = strchr(token, '=');

            if (NULL != colon && (NULL == eq || colon < eq))
            {
                // Bank form: label:reg=acc,reg=acc
                char *item;
                char *items;

                *colon = 0;
                name = token;
                items = colon + 1;

                for (item = AgNextToken(items, ',', &items); item; item = AgNextToken(items, ',', &items))
                {
                    char *ieq = strchr(item, '=');
                    char *rname;
                    int acc, idx;

                    if (NULL == ieq)
                    {
                        snprintf(Err, ErrSize, "bad register item '%s'", item);
                        return -1;
                    }

                    *ieq = 0;
                    rname = item;
                    acc = AgAccessFromString(ieq + 1);
                    if (acc < 0)
                    {
                        snprintf(Err, ErrSize, "bad access '%s'", ieq + 1);
                        return -1;
                    }

                    idx = AgRegisterIndex(name, rname);
                    if (idx < 0)
                    {
                        snprintf(Err, ErrSize, "unknown register '%s' in bank '%s'", rname, name);
                        return -1;
                    }

                    if (0 == strcmp(name, "gpr")) Graph->Gpr[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "seg")) Graph->Seg[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "fpu")) Graph->Fpu[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "mmx")) Graph->Mmx[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "sse")) Graph->Sse[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "cr")) Graph->Cr[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "dr")) Graph->Dr[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "tr")) Graph->Tr[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "bnd")) Graph->Bnd[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "msk")) Graph->Msk[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "tmm")) Graph->Tmm[idx] = (uint8_t)acc;
                    else if (0 == strcmp(name, "sys")) Graph->Sys[idx] = (uint8_t)acc;
                    else Graph->X87[idx] = (uint8_t)acc;
                }

                continue;
            }
        }

        *eq = 0;
        name = token;
        value = eq + 1;

        if (0 == strcmp(name, "sw"))
        {
            Graph->StackWords = (uint8_t)atoi(value);
        }
        else if (0 == strcmp(name, "ft")) Graph->FlagsTested = (uint32_t)strtoul(value, NULL, 0);
        else if (0 == strcmp(name, "fm")) Graph->FlagsModified = (uint32_t)strtoul(value, NULL, 0);
        else if (0 == strcmp(name, "fs")) Graph->FlagsSet = (uint32_t)strtoul(value, NULL, 0);
        else if (0 == strcmp(name, "fc")) Graph->FlagsCleared = (uint32_t)strtoul(value, NULL, 0);
        else if (0 == strcmp(name, "fu")) Graph->FlagsUndefined = (uint32_t)strtoul(value, NULL, 0);
        else
        {
            int acc = AgAccessFromString(value);
            uint8_t *dst = NULL;

            if (acc < 0)
            {
                snprintf(Err, ErrSize, "bad access '%s'", value);
                return -1;
            }

            if (0 == strcmp(name, "mem")) dst = &Graph->Mem;
            else if (0 == strcmp(name, "shadow")) dst = &Graph->ShadowMem;
            else if (0 == strcmp(name, "stack")) dst = &Graph->Stack;
            else if (0 == strcmp(name, "rfl")) dst = &Graph->Flags;
            else if (0 == strcmp(name, "rip")) dst = &Graph->Rip;
            else if (0 == strcmp(name, "cs")) dst = &Graph->Cs;
            else if (0 == strcmp(name, "ssp")) dst = &Graph->Ssp;
            else if (0 == strcmp(name, "mxcsr")) dst = &Graph->Mxcsr;
            else if (0 == strcmp(name, "pkru")) dst = &Graph->Pkru;
            else if (0 == strcmp(name, "uif")) dst = &Graph->Uif;

            if (NULL == dst)
            {
                snprintf(Err, ErrSize, "unknown field '%s'", name);
                return -1;
            }

            *dst = (uint8_t)acc;
        }
    }

    return 0;
}

int
AgHasRegisterAccessBeyond(
    const AG_GRAPH *Right,
    const AG_GRAPH *Left
)
{
    unsigned i;

#define AG_BEYOND(BANK, COUNT)                                                              \
    for (i = 0; i < (COUNT); i++)                                                           \
    {                                                                                       \
        if (Right->BANK[i] & ~Left->BANK[i] & (AG_READ | AG_WRITE | AG_COND_READ |          \
                                                AG_COND_WRITE | AG_PREFETCH))               \
        {                                                                                   \
            return 1;                                                                       \
        }                                                                                   \
    }

    AG_BEYOND(Gpr, ND_MAX_GPR_REGS)
    AG_BEYOND(Seg, ND_MAX_SEG_REGS)
    AG_BEYOND(Fpu, ND_MAX_FPU_REGS)
    AG_BEYOND(Mmx, ND_MAX_MMX_REGS)
    AG_BEYOND(Sse, ND_MAX_SSE_REGS)
    AG_BEYOND(Cr, ND_MAX_CR_REGS)
    AG_BEYOND(Dr, ND_MAX_DR_REGS)
    AG_BEYOND(Tr, ND_MAX_TR_REGS)
    AG_BEYOND(Bnd, ND_MAX_BND_REGS)
    AG_BEYOND(Msk, ND_MAX_MSK_REGS)
    AG_BEYOND(Tmm, ND_MAX_TILE_REGS)
    AG_BEYOND(Sys, ND_MAX_SYS_REGS)
    AG_BEYOND(X87, ND_MAX_X87_REGS)

#undef AG_BEYOND

    return 0;
}

int
AgCompare(
    const AG_GRAPH *Expected,
    const AG_GRAPH *Actual,
    char *Difference,
    size_t DifferenceSize
)
{
    unsigned i;

#define AG_CMP_SCALAR(FIELD, NAME)                                                          \
    if (Expected->FIELD != Actual->FIELD)                                                   \
    {                                                                                       \
        char e[16], a[16];                                                                  \
        AgAccessToString(Expected->FIELD, e);                                               \
        AgAccessToString(Actual->FIELD, a);                                                 \
        snprintf(Difference, DifferenceSize, "%s expected=%s actual=%s", NAME, e, a);       \
        return -1;                                                                          \
    }

#define AG_CMP_BANK(BANK, COUNT, NAMES)                                                     \
    for (i = 0; i < (COUNT); i++)                                                           \
    {                                                                                       \
        if (Expected->BANK[i] != Actual->BANK[i])                                           \
        {                                                                                   \
            char e[16], a[16];                                                              \
            AgAccessToString(Expected->BANK[i], e);                                          \
            AgAccessToString(Actual->BANK[i], a);                                            \
            snprintf(Difference, DifferenceSize, "%s expected=%s actual=%s", (NAMES)[i], e, a); \
            return -1;                                                                      \
        }                                                                                   \
    }

    AG_CMP_SCALAR(Mem, "mem");
    AG_CMP_SCALAR(ShadowMem, "shadow");
    AG_CMP_SCALAR(Stack, "stack");
    AG_CMP_SCALAR(Flags, "rfl");
    AG_CMP_SCALAR(Rip, "rip");
    AG_CMP_SCALAR(Cs, "cs");
    AG_CMP_SCALAR(Ssp, "ssp");
    AG_CMP_SCALAR(Mxcsr, "mxcsr");
    AG_CMP_SCALAR(Pkru, "pkru");
    AG_CMP_SCALAR(Uif, "uif");

    if (Expected->StackWords != Actual->StackWords)
    {
        snprintf(Difference, DifferenceSize, "sw expected=%u actual=%u",
                 Expected->StackWords, Actual->StackWords);
        return -1;
    }

    AG_CMP_BANK(Gpr, ND_MAX_GPR_REGS, (const char *const *)gGprNames);
    AG_CMP_BANK(Seg, ND_MAX_SEG_REGS, (const char *const *)gSegNames);
    AG_CMP_BANK(Cr, ND_MAX_CR_REGS, (const char *const *)gCrNames);
    AG_CMP_BANK(Dr, ND_MAX_DR_REGS, (const char *const *)gDrNames);
    AG_CMP_BANK(Sys, ND_MAX_SYS_REGS, gSysNames);

#define AG_CMP_INDEXED(BANK, COUNT, PREFIX)                                                 \
    for (i = 0; i < (COUNT); i++)                                                           \
    {                                                                                       \
        if (Expected->BANK[i] != Actual->BANK[i])                                           \
        {                                                                                   \
            char e[16], a[16];                                                              \
            AgAccessToString(Expected->BANK[i], e);                                          \
            AgAccessToString(Actual->BANK[i], a);                                            \
            snprintf(Difference, DifferenceSize, "%s%u expected=%s actual=%s", PREFIX, i, e, a); \
            return -1;                                                                      \
        }                                                                                   \
    }

    AG_CMP_INDEXED(Fpu, ND_MAX_FPU_REGS, "st");
    AG_CMP_INDEXED(Mmx, ND_MAX_MMX_REGS, "mm");
    AG_CMP_INDEXED(Sse, ND_MAX_SSE_REGS, "xmm");
    AG_CMP_INDEXED(Tr, ND_MAX_TR_REGS, "tr");
    AG_CMP_INDEXED(Bnd, ND_MAX_BND_REGS, "bnd");
    AG_CMP_INDEXED(Msk, ND_MAX_MSK_REGS, "k");
    AG_CMP_INDEXED(Tmm, ND_MAX_TILE_REGS, "tmm");
    AG_CMP_INDEXED(X87, ND_MAX_X87_REGS, "x87_");

#define AG_CMP_FLAGS(FIELD, NAME)                                                           \
    if (Expected->FIELD != Actual->FIELD)                                                   \
    {                                                                                       \
        snprintf(Difference, DifferenceSize, "%s expected=0x%x actual=0x%x", NAME,          \
                 Expected->FIELD, Actual->FIELD);                                           \
        return -1;                                                                          \
    }

    AG_CMP_FLAGS(FlagsTested, "ft");
    AG_CMP_FLAGS(FlagsModified, "fm");
    AG_CMP_FLAGS(FlagsSet, "fs");
    AG_CMP_FLAGS(FlagsCleared, "fc");
    AG_CMP_FLAGS(FlagsUndefined, "fu");

#undef AG_CMP_SCALAR
#undef AG_CMP_BANK
#undef AG_CMP_INDEXED
#undef AG_CMP_FLAGS

    Difference[0] = 0;
    return 0;
}
