/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Canonical, structure-based description of the read/write graph that a decoded instruction
 * exposes. Two independent views of the same instruction are built:
 *   - the "operand view", aggregated from INSTRUX.Operands using the semantic rules below;
 *   - the "map view", aggregated from NdGetFullAccessMap.
 * Both are compared against the hand-written expectation of each test sample, and against each
 * other. Nothing here depends on the textual disassembly, so rendering changes are reported as
 * a separate TEXT verdict and can never be confused with an access-graph regression.
 */
#ifndef ACCESS_GRAPH_H
#define ACCESS_GRAPH_H

#include <stdint.h>
#include <stddef.h>

#include "bddisasm.h"

#define AG_NONE 0x00
#define AG_READ 0x01
#define AG_WRITE 0x02
#define AG_COND_READ 0x04
#define AG_COND_WRITE 0x08
#define AG_PREFETCH 0x10

typedef struct _AG_GRAPH
{
    uint8_t     Mem;        // Plain data memory (not stack, not shadow stack, not address generation).
    uint8_t     ShadowMem;  // Shadow stack memory (IsShadowStack).
    uint8_t     Stack;      // Stack memory (IsStack).
    uint8_t     Flags;      // RFLAGS aggregate access.
    uint8_t     Rip;
    uint8_t     Cs;
    uint8_t     Ssp;
    uint8_t     Mxcsr;
    uint8_t     Pkru;
    uint8_t     Uif;

    uint8_t     Gpr[ND_MAX_GPR_REGS];
    uint8_t     Seg[ND_MAX_SEG_REGS];
    uint8_t     Fpu[ND_MAX_FPU_REGS];
    uint8_t     Mmx[ND_MAX_MMX_REGS];
    uint8_t     Sse[ND_MAX_SSE_REGS];
    uint8_t     Cr[ND_MAX_CR_REGS];
    uint8_t     Dr[ND_MAX_DR_REGS];
    uint8_t     Tr[ND_MAX_TR_REGS];
    uint8_t     Bnd[ND_MAX_BND_REGS];
    uint8_t     Msk[ND_MAX_MSK_REGS];
    uint8_t     Tmm[ND_MAX_TILE_REGS];
    uint8_t     Sys[ND_MAX_SYS_REGS];
    uint8_t     X87[ND_MAX_X87_REGS];

    uint8_t     StackWords;

    // Per-bit flag detail, exactly as reported by INSTRUX.FlagsAccess. Used to cross check that
    // the aggregate RFLAGS access does not contradict the detailed information.
    uint32_t    FlagsTested;
    uint32_t    FlagsModified;
    uint32_t    FlagsSet;
    uint32_t    FlagsCleared;
    uint32_t    FlagsUndefined;
} AG_GRAPH;

//
// Build the operand-derived view. This applies the implicit-access rules that the operand list
// does not spell out directly:
//   - a stack operand reads and writes RSP and reads SS;
//   - a memory operand reads its segment, base and (non-VSIB) index registers;
//   - address-generation (LEA) operands read base/index but perform no memory access.
//
void
AgBuildOperandView(
    const INSTRUX *Instrux,
    AG_GRAPH *Graph
);

//
// Build the view derived from NdGetFullAccessMap. Note that the public map merges shadow stack
// accesses into MemAccess, so that is reconstructed as Mem|ShadowMem for comparisons.
//
NDSTATUS
AgBuildMapView(
    const INSTRUX *Instrux,
    AG_GRAPH *Graph
);

//
// Parse a compact expectation string into a graph. Returns 0 on success, and fills Err with a
// description of the first syntax problem otherwise.
//
int
AgParseExpected(
    const char *Text,
    AG_GRAPH *Graph,
    char *Err,
    size_t ErrSize
);

//
// Serialize a graph back to the compact expectation syntax (canonical, sorted form). Used both
// for diagnostics and to show the expectation that failed.
//
void
AgToString(
    const AG_GRAPH *Graph,
    char *Buffer,
    size_t BufferSize
);

//
// Returns non-zero if any register (of any kind) in Right has an access bit that Left does not.
// Used to test whether a register bank contributed anything to the access map.
//
int
AgHasRegisterAccessBeyond(
    const AG_GRAPH *Right,
    const AG_GRAPH *Left
);

//
// Compare two graphs, field by field. Any difference is written to Difference (first difference
// only, in "field expected/actual" form). Returns 0 when the graphs are equal.
//
int
AgCompare(
    const AG_GRAPH *Expected,
    const AG_GRAPH *Actual,
    char *Difference,
    size_t DifferenceSize
);

#endif // ACCESS_GRAPH_H
