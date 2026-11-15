/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 *
 * Access-graph integration tests.
 *
 * For each minimal machine-code sample this checks three independent things:
 *
 *   1. OPERAND GRAPH - the read/write set rebuilt from INSTRUX.Operands, including the implicit
 *      effects that are not spelled out as operands (stack pointer updates, segment reads,
 *      addressing registers). Compared against a hand-written expectation.
 *   2. MAP GRAPH     - the same set as reported by NdGetFullAccessMap. Compared against the same
 *      expectation, so a disagreement between the two public views is caught.
 *   3. TEXT          - the formatted instruction. Kept separate from the graphs, and further split
 *      into an exact and a whitespace-normalized comparison, so a column-width change is reported
 *      as cosmetic instead of as a data-flow regression.
 *
 * A fourth phase sweeps a byte grid and checks structural invariants that must hold for every
 * instruction (addressing-only registers are never written, no unresolved register bank, block
 * operands expose their count, flag detail never contradicts the aggregate RFLAGS access, ...).
 *
 * Samples whose expectation encodes architecturally correct behaviour that the decoder currently
 * does not produce carry a Deviation note. They are reported as KNOWN-DEVIATION and do not fail
 * the run; if such a sample starts passing, it is reported as FIXED so the note can be removed.
 *
 * Exit code: 0 when every non-deviation sample passes and the sweep finds nothing unexpected,
 * 1 otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "bddisasm.h"
#include "access_graph.h"

#define MAX_BYTES 15

typedef struct _SAMPLE
{
    const char  *Name;
    const char  *Why;
    uint8_t     Mode;
    uint8_t     Bytes[MAX_BYTES];
    uint8_t     Length;
    const char  *Expected;
    const char  *ExpectedText;
    const char  *Deviation;
} SAMPLE;

/*
 * ---------------------------------------------------------------------------------------------
 * Stack operations.
 * A stack operand is implicit for most integer instructions. Its effect on RSP/SS is not encoded
 * in the operand list, so it has to be reconstructed; missing it silently breaks data-flow.
 * ---------------------------------------------------------------------------------------------
 */
static const SAMPLE gSamples[] =
{
    // ---- stack ----
    { "push_r64", "push reg: writes stack, reads reg, RSP read+write", ND_CODE_64,
      { 0x50 }, 1,
      "stack=W;sw=1;gpr:rax=R,rsp=RW;seg:ss=R",
      "PUSH      rax", NULL },

    { "push_imm8", "push imm: no register operand, but RSP is still updated", ND_CODE_64,
      { 0x6A, 0x01 }, 2,
      "stack=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "PUSH      0x0000000000000001", NULL },

    { "push_mem_rsp", "push [rsp]: explicit mem read plus implicit stack write, same register", ND_CODE_64,
      { 0xFF, 0x34, 0x24 }, 3,
      "mem=R;stack=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "PUSH      qword ptr [rsp]", NULL },

    { "pop_r64", "pop reg: reads stack, writes reg, RSP read+write", ND_CODE_64,
      { 0x58 }, 1,
      "stack=R;sw=1;gpr:rax=W,rsp=RW;seg:ss=R",
      "POP       rax", NULL },

    { "pop_mem_32", "pop [esp] (32-bit): memory write happens after the stack read", ND_CODE_32,
      { 0x8F, 0x04, 0x24 }, 3,
      "mem=W;stack=R;sw=1;gpr:rsp=RW;seg:ss=R",
      "POP       dword ptr [esp]", NULL },

    { "push_ax_64", "push ax: 16-bit payload, 64-bit stack pointer still moves by 2 bytes", ND_CODE_64,
      { 0x66, 0x50 }, 2,
      "stack=W;sw=1;gpr:rax=R,rsp=RW;seg:ss=R",
      "PUSH      ax", NULL },

    { "push_imm8_16", "push imm in 16-bit mode: SP width follows the stack mode", ND_CODE_16,
      { 0x6A, 0x01 }, 2,
      "stack=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "PUSH      0x0001", NULL },

    { "pushfq", "pushfq reads the flags register as a whole", ND_CODE_64,
      { 0x9C }, 1,
      "stack=W;rfl=R;sw=1;gpr:rsp=RW;seg:ss=R",
      "PUSHFQ    ", NULL },

    { "popfq", "popfq writes the flags register as a whole", ND_CODE_64,
      { 0x9D }, 1,
      "stack=R;rfl=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "POPFQ     ", NULL },

    { "call_rel32", "call: RIP read+write, stack write, shadow-stack write", ND_CODE_64,
      { 0xE8, 0x00, 0x00, 0x00, 0x00 }, 5,
      "shadow=W;stack=W;rip=RW;sw=1;gpr:rsp=RW;seg:ss=R",
      "CALL      0x5", NULL },

    { "ret", "ret: pops the return address, writes RIP", ND_CODE_64,
      { 0xC3 }, 1,
      "shadow=R;stack=R;rip=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "RETN", NULL },

    { "ret_imm16", "ret imm16: the immediate adjusts RSP but is not a register", ND_CODE_64,
      { 0xC2, 0x08, 0x00 }, 3,
      "shadow=R;stack=R;rip=W;sw=1;gpr:rsp=RW;seg:ss=R",
      "RETN      0x0008", NULL },

    { "leave", "leave: RBP is read then written, RSP is written, stack is read", ND_CODE_64,
      { 0xC9 }, 1,
      "stack=R;sw=1;gpr:rbp=RW,rsp=RW;seg:ss=R",
      "LEAVE", NULL },

    { "enter_l0", "enter level 0: [RBP] is read for the frame chain, stack written", ND_CODE_64,
      { 0xC8, 0x10, 0x00, 0x00 }, 4,
      "mem=R;stack=W;sw=1;gpr:rbp=RW,rsp=RW;seg:ss=R",
      "ENTER     0x0010, 0x00", NULL },

    { "pushad_32", "pushad: one bank operand and eight stack words", ND_CODE_32,
      { 0x60 }, 1,
      "stack=W;sw=8;gpr:rax=R,rcx=R,rdx=R,rbx=R,rsp=RW,rbp=R,rsi=R,rdi=R;seg:ss=R",
      "PUSHAD",
      "PUSHAD emits ND_OP_BANK with no GPR expansion; only RSP/SS appear in the access map, so "
      "the eight registers pushed are invisible to data-flow tracking" },

    { "popad_32", "popad: bank destination, eight stack words", ND_CODE_32,
      { 0x61 }, 1,
      "stack=R;sw=8;gpr:rax=W,rcx=W,rdx=W,rbx=W,rsp=RW,rbp=W,rsi=W,rdi=W;seg:ss=R",
      "POPAD",
      "POPAD emits ND_OP_BANK with no GPR expansion; the eight registers restored are invisible "
      "to data-flow tracking" },

    { "pusha_16", "pusha must expose all eight GPR reads, not just AX",
      ND_CODE_16, { 0x60 }, 1,
      "stack=W;sw=8;gpr:rax=R,rcx=R,rdx=R,rbx=R,rsp=RW,rbp=R,rsi=R,rdi=R;seg:ss=R",
      "PUSHA",
      "PUSHA exposes a block GPR operand but the block is emitted with Count=1 and only AX; the "
      "other seven GPRs read by PUSHA are missing from both views" },

    // ---- string instructions ----
    { "movsb_64", "movsb: two string memory operands, both index registers written back", ND_CODE_64,
      { 0xA4 }, 1,
      "mem=RW;rfl=R;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400",
      "MOVSB", NULL },

    { "rep_movsb_64", "rep movsb: repetition makes every access conditional, RCX counted down", ND_CODE_64,
      { 0xF3, 0xA4 }, 2,
      "mem=CRCW;rfl=RW;gpr:rcx=RCW,rsi=RCW,rdi=RCW;seg:es=R,ds=R;ft=0x400",
      "REP MOVSB", NULL },

    { "movsq_64", "movsq: 8-byte element, same register graph as movsb", ND_CODE_64,
      { 0x48, 0xA5 }, 2,
      "mem=RW;rfl=R;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400",
      "MOVSQ", NULL },

    { "movsb_addrsz32_64", "movsb with address-size override: accesses unchanged, index width changes",
      ND_CODE_64, { 0x67, 0xA4 }, 2,
      "mem=RW;rfl=R;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400",
      "MOVSB", NULL },

    { "movsw_16", "movsw in 16-bit mode: 16-bit index registers, same graph", ND_CODE_16,
      { 0xA5 }, 1,
      "mem=RW;rfl=R;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400",
      "MOVSW", NULL },

    { "movsw_addrsz32_16", "movsw with address-size override in 16-bit mode", ND_CODE_16,
      { 0x67, 0xA5 }, 2,
      "mem=RW;rfl=R;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400",
      "MOVSW", NULL },

    { "cmpsb_64", "cmps compares and therefore writes the arithmetic flags",
      ND_CODE_64, { 0xA6 }, 1,
      "mem=R;rfl=RW;gpr:rsi=RW,rdi=RW;seg:es=R,ds=R;ft=0x400;fm=0x8d5",
      "CMPSB",
      "CMPS reports RflAccess=read although FlagsAccess.Modified says CF/PF/AF/ZF/SF/OF are "
      "written; the aggregate access map therefore hides a flags write (SCAS, which shares the "
      "flag template, does report read+write)" },

    { "scasb_64", "scas reads AL and memory, writes flags and RDI", ND_CODE_64,
      { 0xAE }, 1,
      "mem=R;rfl=RW;gpr:rax=R,rdi=RW;seg:es=R;ft=0x400;fm=0x8d5",
      "SCASB", NULL },

    { "stosb_64", "stos writes memory and RDI, reads AL; DF is only tested", ND_CODE_64,
      { 0xAA }, 1,
      "mem=W;rfl=R;gpr:rax=R,rdi=RW;seg:es=R;ft=0x400",
      "STOSB", NULL },

    { "lodsb_64", "lods reads memory, writes AL and RSI", ND_CODE_64,
      { 0xAC }, 1,
      "mem=R;rfl=R;gpr:rax=W,rsi=RW;seg:ds=R;ft=0x400",
      "LODSB", NULL },

    { "rep_stosb_64", "rep stos: memory write and RDI/RCX/RFLAGS writes are all conditional", ND_CODE_64,
      { 0xF3, 0xAA }, 2,
      "mem=CW;rfl=RW;gpr:rax=R,rcx=RCW,rdi=RCW;seg:es=R;ft=0x400",
      "REP STOSB", NULL },

    { "repe_cmpsb_64", "repe cmps: ZF is tested to decide repetition and also written", ND_CODE_64,
      { 0xF3, 0xA6 }, 2,
      "mem=CR;rfl=RW;gpr:rcx=RCW,rsi=RCW,rdi=RCW;seg:es=R,ds=R;ft=0x440;fm=0x8d5",
      "REPZ CMPSB", NULL },

    { "repne_scasb_64", "repne scas: ZF tested for the loop, all arithmetic flags written", ND_CODE_64,
      { 0xF2, 0xAE }, 2,
      "mem=CR;rfl=RW;gpr:rax=R,rcx=RCW,rdi=RCW;seg:es=R;ft=0x440;fm=0x8d5",
      "REPNZ SCASB", NULL },

    // ---- conditional writes ----
    { "cmovz_eax_ebx", "cmov: destination is conditionally written, condition flag is read", ND_CODE_64,
      { 0x0F, 0x44, 0xC3 }, 3,
      "rfl=R;gpr:rax=CW,rbx=R;ft=0x40",
      "CMOVZ     eax, ebx", NULL },

    { "cmovnz_eax_mem", "cmov from memory: memory read is unconditional, destination write is not",
      ND_CODE_64, { 0x0F, 0x45, 0x04, 0x08 }, 4,
      "mem=R;rfl=R;gpr:rax=RCW,rcx=R;seg:ds=R;ft=0x40",
      "CMOVNZ    eax, dword ptr [rax+rcx]", NULL },

    { "setz_al", "setcc: unconditional byte write, condition flag read", ND_CODE_64,
      { 0x0F, 0x94, 0xC0 }, 3,
      "rfl=R;gpr:rax=W;ft=0x40",
      "SETZ      al", NULL },

    { "setz_mem", "setcc to memory: memory is written unconditionally", ND_CODE_64,
      { 0x0F, 0x94, 0x00 }, 3,
      "mem=W;rfl=R;gpr:rax=R;seg:ds=R;ft=0x40",
      "SETZ      byte ptr [rax]", NULL },

    { "cmpxchg_mem", "cmpxchg: memory and EAX are conditionally written, ZF written", ND_CODE_64,
      { 0x0F, 0xB0, 0x08 }, 3,
      "mem=RCW;rfl=W;gpr:rax=RCW,rcx=R;seg:ds=R;fm=0x8d5",
      "CMPXCHG   byte ptr [rax], cl", NULL },

    { "xadd_mem", "xadd: unconditional read-modify-write on memory and the register", ND_CODE_64,
      { 0x0F, 0xC0, 0x08 }, 3,
      "mem=RW;rfl=W;gpr:rax=R,rcx=RW;seg:ds=R;fm=0x8d5",
      "XADD      byte ptr [rax], cl", NULL },

    { "jz_rel8", "jz: RIP conditionally written, condition flag read, no register alias", ND_CODE_64,
      { 0x74, 0x00 }, 2,
      "rfl=R;rip=CRCW;ft=0x40",
      "JZ        0x2", NULL },

    { "loop_rel8", "loop: RCX decremented unconditionally, RIP conditionally written", ND_CODE_64,
      { 0xE2, 0x00 }, 2,
      "rfl=R;rip=CRCW;gpr:rcx=RW;ft=0",
      "LOOP      0x2", NULL },

    { "int3", "int3: CS/RIP/RSP/stack/shadow stack read-modify-write, flags read and written",
      ND_CODE_64, { 0xCC }, 1,
      "shadow=W;stack=RW;rfl=RW;rip=RW;cs=RW;sw=3;gpr:rsp=RW;seg:ss=R;ft=0x20000;fm=0x74300",
      "INT3",
      "INT tests the VM flag (FlagsAccess.Tested) but reports RflAccess=write only; the aggregate "
      "map omits the flags read" },

    // ---- address widths ----
    { "mov_sib_64", "64-bit SIB addressing: base and index are read, never written", ND_CODE_64,
      { 0x8B, 0x04, 0x4B }, 3,
      "mem=R;gpr:rax=W,rbx=R,rcx=R;seg:ds=R",
      "MOV       eax, dword ptr [rbx+rcx*2]", NULL },

    { "mov_sib_addrsz32_64", "address-size override in 64-bit mode: EIP-relative-free 32-bit base/index",
      ND_CODE_64, { 0x67, 0x8B, 0x04, 0x4B }, 4,
      "mem=R;gpr:rax=W,rbx=R,rcx=R;seg:ds=R",
      "MOV       eax, dword ptr [ebx+ecx*2]", NULL },

    { "mov_sib_32", "32-bit mode SIB addressing", ND_CODE_32,
      { 0x8B, 0x04, 0x4B }, 3,
      "mem=R;gpr:rax=W,rbx=R,rcx=R;seg:ds=R",
      "MOV       eax, dword ptr [ebx+ecx*2]", NULL },

    { "mov_bxsi_16", "16-bit addressing: BX and SI are the base/index registers", ND_CODE_16,
      { 0x8B, 0x00 }, 2,
      "mem=R;gpr:rax=W,rbx=R,rsi=R;seg:ds=R",
      "MOV       ax, word ptr [bx+si]", NULL },

    { "mov_addrsz32_16", "16-bit mode with 32-bit addressing: EAX is the base and is also the destination",
      ND_CODE_16, { 0x67, 0x8B, 0x00 }, 3,
      "mem=R;gpr:rax=RW;seg:ds=R",
      "MOV       ax, word ptr [eax]", NULL },

    { "mov_disp32_only_64", "SIB with no base and no index: encoding slots 4/5 hold no register",
      ND_CODE_64, { 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00 }, 7,
      "mem=R;gpr:rax=W;seg:ds=R",
      "MOV       eax, dword ptr [0x0]", NULL },

    { "mov_rip_rel", "RIP-relative: no base/index register is read", ND_CODE_64,
      { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 }, 6,
      "mem=R;gpr:rax=W;seg:ds=R",
      "MOV       eax, dword ptr [rel 0x6]", NULL },

    { "lea_sib", "lea: address generation reads base/index but performs no memory access", ND_CODE_64,
      { 0x48, 0x8D, 0x04, 0x4B }, 4,
      "gpr:rax=W,rbx=R,rcx=R",
      "LEA       rax, [rbx+rcx*2]", NULL },

    { "lea_rip_rel", "lea with RIP-relative addressing reads no GPR and touches no memory", ND_CODE_64,
      { 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 }, 6,
      "gpr:rax=W",
      "LEA       eax, [rel 0x6]", NULL },

    { "mov_al_ah", "high-byte aliasing: AH and AL are the same tracked GPR", ND_CODE_64,
      { 0x88, 0xE0 }, 2,
      "gpr:rax=RW",
      "MOV       al, ah", NULL },

    { "mov_moffs_64", "moffset form: absolute displacement, DS read, no GPR addressing", ND_CODE_64,
      { 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 9,
      "mem=R;gpr:rax=W;seg:ds=R",
      "MOV       al, byte ptr [0x0]", NULL },

    { "prefetch_rax", "prefetch marks the memory operand as prefetched, not read", ND_CODE_64,
      { 0x0F, 0x0D, 0x08 }, 3,
      "mem=P;gpr:rax=R;seg:ds=R",
      "PREFETCHW byte ptr [rax]", NULL },

    { "xlatb", "xlat reads [RBX+AL] and writes AL", ND_CODE_64,
      { 0xD7 }, 1,
      "mem=R;gpr:rax=RW,rbx=R;seg:ds=R",
      "XLATB", NULL },

    // ---- remaining register-bank / implicit-flag cases ----
    { "fcmovb", "x87 conditional move: ST0 conditionally written, CF alias tested", ND_CODE_64,
      { 0xDA, 0xC1 }, 2,
      "rfl=RW;fpu:st0=CW,st1=R;sys:ldtr=RW;ft=0x1",
      "FCMOVB    st0, st1",
      "FCMOVcc tests the CF bit (here standing for x87 C0) but RflAccess is write-only, so the "
      "aggregate map hides the flags read" },

    { "vzeroall", "vzeroall: the bank must expand to the SSE registers it zeroes",
      ND_CODE_64, { 0xC5, 0xFC, 0x77 }, 3,
      "sse:xmm0=W,xmm1=W,xmm2=W,xmm3=W,xmm4=W,xmm5=W,xmm6=W,xmm7=W,xmm8=W,xmm9=W,xmm10=W,"
      "xmm11=W,xmm12=W,xmm13=W,xmm14=W,xmm15=W",
      "VZEROALL",
      "VZEROALL/VZEROUPPER carry ND_OP_BANK(write) but NdGetFullAccessMap leaves the SSE bank "
      "empty, so the registers they zero are invisible in the map" },

    { "fxsave", "fxsave: register bank must expand to the x87/SSE state it saves",
      ND_CODE_64, { 0x0F, 0xAE, 0x00 }, 3,
      "mem=W;gpr:rax=R;seg:ds=R;fpu:st0=R,st1=R,st2=R,st3=R,st4=R,st5=R,st6=R,st7=R;"
      "sse:xmm0=R,xmm1=R,xmm2=R,xmm3=R,xmm4=R,xmm5=R,xmm6=R,xmm7=R,xmm8=R,xmm9=R,xmm10=R,"
      "xmm11=R,xmm12=R,xmm13=R,xmm14=R,xmm15=R",
      "FXSAVE    [rax]",
      "FXSAVE carries an implicit ND_OP_BANK(read) but NdGetFullAccessMap expands banks only for "
      "FNSAVE/FRSTOR and the XSAVE family; the x87/SSE/MXCSR state reads are absent from the map" },

    { "lgdt", "lgdt writes GDTR from memory: the descriptor-table register must be distinguishable",
      ND_CODE_64, { 0x0F, 0x01, 0x10 }, 3,
      "mem=R;gpr:rax=R;seg:ds=R;sys:gdtr=W",
      "LGDT      tbyte ptr [rax]", NULL },

    { "fldcw", "fldcw writes the x87 control word - a different register from GDTR",
      ND_CODE_64, { 0xD9, 0x28 }, 2,
      "mem=R;gpr:rax=R;seg:ds=R;sys:gdtr=W,ldtr=W",
      "FLDCW     word ptr [rax]",
      "X87CONTROL/X87TAG/X87STATUS are emitted as ND_REG_SYS with ids 0/1/2, the same slots as "
      "GDTR/IDTR/LDTR. FLDCW and LGDT therefore both report 'sys 0' written, so a data-flow "
      "consumer cannot tell an x87 control-word update from a GDT load" },
};

#define SAMPLE_COUNT ((int)(sizeof(gSamples) / sizeof(gSamples[0])))

typedef enum _VERDICT
{
    VERDICT_PASS = 0,
    VERDICT_FAIL_OPERAND_GRAPH,
    VERDICT_FAIL_MAP_GRAPH,
    VERDICT_FAIL_INVARIANT,
    VERDICT_WARN_TEXT_FORMAT,
    VERDICT_FAIL_TEXT,
    VERDICT_KNOWN_DEVIATION,
    VERDICT_FIXED,
} VERDICT;

static const char *
VerdictName(VERDICT Verdict)
{
    switch (Verdict)
    {
    case VERDICT_PASS: return "PASS";
    case VERDICT_FAIL_OPERAND_GRAPH: return "FAIL(operand-graph)";
    case VERDICT_FAIL_MAP_GRAPH: return "FAIL(map-graph)";
    case VERDICT_FAIL_INVARIANT: return "FAIL(invariant)";
    case VERDICT_WARN_TEXT_FORMAT: return "WARN(text-format)";
    case VERDICT_FAIL_TEXT: return "FAIL(text)";
    case VERDICT_KNOWN_DEVIATION: return "KNOWN-DEVIATION";
    case VERDICT_FIXED: return "FIXED";
    }

    return "?";
}

//
// Collapse whitespace runs and trailing spaces, so a pure padding change can be told apart from a
// real change in the printed operands.
//
static void
NormalizeText(
    const char *In,
    char *Out,
    size_t OutSize
)
{
    size_t o = 0;
    int pendingSpace = 0;

    while (*In && o + 1 < OutSize)
    {
        if (isspace((unsigned char)*In))
        {
            pendingSpace = (o > 0);
        }
        else
        {
            if (pendingSpace)
            {
                Out[o++] = ' ';
                pendingSpace = 0;
                if (o + 1 >= OutSize)
                {
                    break;
                }
            }
            Out[o++] = *In;
        }
        In++;
    }

    Out[o] = 0;
}

//
// Structural invariants that must hold for any decoded instruction. Returns NULL when the
// instruction is consistent, or a static description of the first violated invariant. OutBytes
// receives the minimal encoding, so every finding is reproducible on its own.
//
static const char *
CheckInvariants(
    const INSTRUX *Instrux,
    const AG_GRAPH *OperandView,
    const AG_GRAPH *MapView,
    char *Detail,
    size_t DetailSize
)
{
    static const unsigned AM = ND_ACCESS_READ | ND_ACCESS_WRITE |
                               ND_ACCESS_COND_READ | ND_ACCESS_COND_WRITE | ND_ACCESS_PREFETCH;
    unsigned i, r;

    // The per-operand and per-aggregate stack notion must agree.
    if ((MapView->Stack & AM) != (OperandView->Stack & AM))
    {
        snprintf(Detail, DetailSize, "stack aggregate map=0x%x operands=0x%x",
                 MapView->Stack, OperandView->Stack);
        return "stack-access-disagreement";
    }

    // INSTRUX.MemoryAccess covers stack plus ordinary memory plus shadow stack.
    {
        unsigned expected = (OperandView->Mem | OperandView->Stack | OperandView->ShadowMem) & AM;
        if (((unsigned)Instrux->MemoryAccess & AM) != expected)
        {
            snprintf(Detail, DetailSize, "MemoryAccess=0x%x operands=0x%x",
                     Instrux->MemoryAccess, expected);
            return "memory-access-disagreement";
        }
    }

    // The public map folds shadow-stack accesses into MemAccess.
    if (((MapView->Mem & AM) != ((OperandView->Mem | OperandView->ShadowMem) & AM)) ||
        ((unsigned)Instrux->MemoryAccess & AM) != ((OperandView->Mem | OperandView->Stack |
                                                    OperandView->ShadowMem) & AM))
    {
        snprintf(Detail, DetailSize, "map.Mem=0x%x operand mem=0x%x shadow=0x%x",
                 MapView->Mem, OperandView->Mem, OperandView->ShadowMem);
        return "memory-map-disagreement";
    }

    // Flag detail and the aggregate RFLAGS access must not contradict each other. A tested flag
    // needs a read bit; a written flag needs a write bit.
    {
        unsigned detailRead = Instrux->FlagsAccess.Tested.Raw;
        unsigned detailWrite = Instrux->FlagsAccess.Modified.Raw | Instrux->FlagsAccess.Set.Raw |
                               Instrux->FlagsAccess.Cleared.Raw | Instrux->FlagsAccess.Undefined.Raw;

        if (detailRead && !(Instrux->RflAccess & (ND_ACCESS_READ | ND_ACCESS_COND_READ)))
        {
            snprintf(Detail, DetailSize, "flags tested=0x%x but RflAccess=0x%x",
                     detailRead, Instrux->RflAccess);
            return "flags-read-not-aggregated";
        }

        if (detailWrite && !(Instrux->RflAccess & (ND_ACCESS_WRITE | ND_ACCESS_COND_WRITE)))
        {
            snprintf(Detail, DetailSize, "flags written=0x%x but RflAccess=0x%x",
                     detailWrite, Instrux->RflAccess);
            return "flags-write-not-aggregated";
        }
    }

    // Every register access the operands imply must be present in the map. This catches addressing
    // registers whose read silently disappears, which the write-only check below cannot see.
    if (AgHasRegisterAccessBeyond(OperandView, MapView))
    {
        unsigned k;

        for (k = 0; k < ND_MAX_GPR_REGS; k++)
        {
            if (OperandView->Gpr[k] & ~MapView->Gpr[k])
            {
                snprintf(Detail, DetailSize,
                         "gpr %u accessed 0x%x by operands but 0x%x by the map",
                         k, OperandView->Gpr[k], MapView->Gpr[k]);
                break;
            }
        }

        if (0 == Detail[0])
        {
            snprintf(Detail, DetailSize, "map omits a register access implied by the operands");
        }

        return "map-drops-register-access";
    }

    // Every GPR write reported by the map must be justified by a register operand with the same
    // number, by a block operand that covers it, or by the implicit stack pointer update. This is
    // what stops address-generation registers from being reported as modified.
    for (r = 0; r < ND_MAX_GPR_REGS; r++)
    {
        int justified = 0;

        if (0 == (MapView->Gpr[r] & (AG_WRITE | AG_COND_WRITE)))
        {
            continue;
        }

        for (i = 0; i < Instrux->OperandsCount && !justified; i++)
        {
            const ND_OPERAND *op = &Instrux->Operands[i];

            if (ND_OP_REG == op->Type && ND_REG_GPR == op->Info.Register.Type &&
                (op->Access.Write || op->Access.CondWrite))
            {
                unsigned base = op->Info.Register.IsHigh8 ? (op->Info.Register.Reg - 4) : op->Info.Register.Reg;
                unsigned count = op->Info.Register.Count ? op->Info.Register.Count : 1;

                if (r >= base && r < base + count)
                {
                    justified = 1;
                }
            }

            if (ND_OP_MEM == op->Type && op->Info.Memory.IsStack && NDR_RSP == r)
            {
                justified = 1;
            }
        }

        if (!justified)
        {
            snprintf(Detail, DetailSize, "gpr %u reported as written by the map, but no operand writes it",
                     r);
            return "unjustified-gpr-write";
        }
    }

    // A block register operand must describe more than one register.
    for (i = 0; i < Instrux->OperandsCount; i++)
    {
        const ND_OPERAND *op = &Instrux->Operands[i];

        if (ND_OP_REG == op->Type && ND_REG_GPR == op->Info.Register.Type &&
            op->Info.Register.IsBlock && op->Info.Register.Count < 2)
        {
            snprintf(Detail, DetailSize, "block GPR operand with Count=%u", op->Info.Register.Count);
            return "block-operand-count";
        }

        if (ND_OP_BANK == op->Type)
        {
            // The bank must contribute at least one register access that no ordinary operand
            // already accounts for. Comparing against the operand view is what makes this
            // sensitive: unrelated accesses (RSP for the stack, a GPR for an explicit operand) do
            // not mask a bank that resolved to nothing.
            if (!AgHasRegisterAccessBeyond(MapView, OperandView))
            {
                snprintf(Detail, DetailSize,
                         "ND_OP_BANK(acc=0x%x) resolved to no register beyond the operands",
                         op->Access.Access);
                return "unresolved-register-bank";
            }
        }
    }

    // x87 control/tag/status words are published as ND_REG_SYS with ids 0..2, which are the same
    // slots used by GDTR/IDTR/LDTR. An x87 instruction touching those slots therefore produces an
    // access that is indistinguishable from a descriptor-table access.
    if (ND_SET_X87 == Instrux->IsaSet)
    {
        for (i = 0; i < Instrux->OperandsCount; i++)
        {
            const ND_OPERAND *op = &Instrux->Operands[i];

            if (ND_OP_REG == op->Type && ND_REG_SYS == op->Info.Register.Type &&
                op->Info.Register.Reg < 3)
            {
                snprintf(Detail, DetailSize,
                         "x87 instruction reports sys slot %u, shared with %s",
                         op->Info.Register.Reg,
                         op->Info.Register.Reg == 0 ? "GDTR/x87control" :
                         (op->Info.Register.Reg == 1 ? "IDTR/x87tag" : "LDTR/x87status"));
                return "sys-slot-aliasing";
            }
        }
    }

    // A stack access with no described words (or vice versa) breaks emulators that size the
    // stack delta from StackWords.
    if ((0 != (OperandView->Stack & AM)) != (0 != OperandView->StackWords))
    {
        snprintf(Detail, DetailSize, "stack access=0x%x StackWords=%u",
                 OperandView->Stack, OperandView->StackWords);
        return "stack-words-mismatch";
    }

    return NULL;
}

static int
CheckText(
    const INSTRUX *Instrux,
    const char *ExpectedText,
    char *Detail,
    size_t DetailSize
)
{
    char text[160];
    char normalizedActual[160];
    char normalizedExpected[160];
    NDSTATUS status;

    if (NULL == ExpectedText)
    {
        return VERDICT_PASS;
    }

#ifdef BDDISASM_NO_FORMAT
    // No formatter compiled in: there is no textual representation to compare.
    (void)Instrux;
    (void)ExpectedText;
    (void)text;
    (void)normalizedActual;
    (void)normalizedExpected;
    (void)status;
    (void)Detail;
    (void)DetailSize;
    return VERDICT_PASS;
#else
    status = NdToText(Instrux, 0, sizeof(text), text);
    if (status != ND_STATUS_SUCCESS)
    {
        snprintf(Detail, DetailSize, "NdToText failed: 0x%x", status);
        return VERDICT_FAIL_TEXT;
    }
#endif

    if (0 == strcmp(text, ExpectedText))
    {
        return VERDICT_PASS;
    }

    NormalizeText(text, normalizedActual, sizeof(normalizedActual));
    NormalizeText(ExpectedText, normalizedExpected, sizeof(normalizedExpected));

    if (0 == strcmp(normalizedActual, normalizedExpected))
    {
        snprintf(Detail, DetailSize, "whitespace-only text change: \"%.96s\" vs \"%.96s\"", text, ExpectedText);
        return VERDICT_WARN_TEXT_FORMAT;
    }

    snprintf(Detail, DetailSize, "expected \"%.80s\" got \"%.80s\"", ExpectedText, text);
    return VERDICT_FAIL_TEXT;
}

//
// Run all checks for one sample. The most severe verdict wins, with graph failures ranked above
// invariant failures, which in turn rank above text failures.
//
static VERDICT
RunSample(
    const SAMPLE *Sample,
    char *Detail,
    size_t DetailSize
)
{
    INSTRUX instrux;
    AG_GRAPH expected;
    AG_GRAPH expectedForMap;
    AG_GRAPH operandView;
    AG_GRAPH mapView;
    char parseError[128];
    char diff[192];
    char invariantDetail[192];
    const char *invariant;
    VERDICT worst = VERDICT_PASS;
    VERDICT verdict;
    NDSTATUS status;

    Detail[0] = 0;

    if (AgParseExpected(Sample->Expected, &expected, parseError, sizeof(parseError)))
    {
        snprintf(Detail, DetailSize, "bad expectation: %s", parseError);
        return VERDICT_FAIL_OPERAND_GRAPH;
    }

    memset(&instrux, 0, sizeof(instrux));

    status = NdDecodeEx(&instrux, Sample->Bytes, Sample->Length, Sample->Mode,
                        Sample->Mode == ND_CODE_64 ? ND_DATA_64 :
                        (Sample->Mode == ND_CODE_32 ? ND_DATA_32 : ND_DATA_16));
    if (status != ND_STATUS_SUCCESS)
    {
        snprintf(Detail, DetailSize, "decode failed: 0x%x", status);
        return VERDICT_FAIL_OPERAND_GRAPH;
    }

    if (instrux.Length != Sample->Length)
    {
        snprintf(Detail, DetailSize, "decoded %u bytes, sample is %u bytes",
                 instrux.Length, Sample->Length);
        return VERDICT_FAIL_OPERAND_GRAPH;
    }

    AgBuildOperandView(&instrux, &operandView);

    if (AgBuildMapView(&instrux, &mapView) != ND_STATUS_SUCCESS)
    {
        snprintf(Detail, DetailSize, "NdGetFullAccessMap failed");
        return VERDICT_FAIL_MAP_GRAPH;
    }

    // CsAccess has no equivalent in ND_ACCESS_MAP; keep it on the map view so the two views are
    // directly comparable.
    mapView.Cs = (uint8_t)instrux.CsAccess;

    // 1. Operand view against the expectation.
    if (AgCompare(&expected, &operandView, diff, sizeof(diff)))
    {
        snprintf(Detail, DetailSize, "operand-graph: %s", diff);
        worst = VERDICT_FAIL_OPERAND_GRAPH;
    }

    // 2. Map view against the same expectation, with the documented fold of shadow stack into
    //    the plain memory bucket.
    expectedForMap = expected;
    expectedForMap.Mem |= expectedForMap.ShadowMem;
    expectedForMap.ShadowMem = 0;

    if (AgCompare(&expectedForMap, &mapView, diff, sizeof(diff)))
    {
        if (VERDICT_PASS == worst)
        {
            snprintf(Detail, DetailSize, "map-graph: %s", diff);
            worst = VERDICT_FAIL_MAP_GRAPH;
        }
        else
        {
            size_t used = strlen(Detail);
            snprintf(Detail + used, DetailSize - used, "; map-graph: %s", diff);
        }
    }

    // 3. Structural invariants.
    invariantDetail[0] = 0;
    invariant = CheckInvariants(&instrux, &operandView, &mapView, invariantDetail,
                                sizeof(invariantDetail));
    if (NULL != invariant)
    {
        if (VERDICT_PASS == worst)
        {
            snprintf(Detail, DetailSize, "%s (%s)", invariant, invariantDetail);
            worst = VERDICT_FAIL_INVARIANT;
        }
        else
        {
            size_t used = strlen(Detail);
            snprintf(Detail + used, DetailSize - used, "; %s (%s)", invariant, invariantDetail);
        }
    }

    // 4. Text is deliberately checked last and separately: it must not mask a graph problem.
    verdict = CheckText(&instrux, Sample->ExpectedText, invariantDetail, sizeof(invariantDetail));
    if (VERDICT_FAIL_TEXT == verdict)
    {
        if (VERDICT_PASS == worst)
        {
            snprintf(Detail, DetailSize, "text: %s", invariantDetail);
            worst = VERDICT_FAIL_TEXT;
        }
    }
    else if (VERDICT_WARN_TEXT_FORMAT == verdict && VERDICT_PASS == worst)
    {
        snprintf(Detail, DetailSize, "%s", invariantDetail);
        worst = VERDICT_WARN_TEXT_FORMAT;
    }

    return worst;
}

static void
PrintBytes(
    const SAMPLE *Sample
)
{
    unsigned i;

    for (i = 0; i < Sample->Length; i++)
    {
        printf("%02X", Sample->Bytes[i]);
    }
}

//
// ---------------------------------------------------------------------------------------------
// Harness self-tests. These do not touch the decoder: they prove that the comparator really does
// tell a graph error apart from a text-only difference, and that the expectation parser round
// trips. Without them, a comparator that silently always returns "equal" would make the whole
// suite vacuous.
// ---------------------------------------------------------------------------------------------
static int gSelfTestFailures;

static void
SelfTestCheck(
    const char *Name,
    int Condition
)
{
    if (!Condition)
    {
        gSelfTestFailures++;
        printf("SELFTEST-FAIL %s\n", Name);
    }
}

static void
RunSelfTests(void)
{
    AG_GRAPH left;
    AG_GRAPH right;
    AG_GRAPH other;
    char err[128];
    char text[512];
    char diff[192];
    char normalized[256];

    // Parser -> printer -> parser must be a fixed point for a representative expectation.
    SelfTestCheck("parse-ok",
                  AgParseExpected("mem=RW;shadow=W;stack=CR;rfl=RW;rip=CRCW;sw=2;"
                                  "gpr:rax=RW,rsp=CW;seg:ds=R,ss=R;fpu:st0=CW;ft=0x440;fm=0x8d5",
                                  &left, err, sizeof(err)) == 0);
    AgToString(&left, text, sizeof(text));
    SelfTestCheck("roundtrip", AgParseExpected(text, &right, err, sizeof(err)) == 0 &&
                               AgCompare(&left, &right, diff, sizeof(diff)) == 0);

    // A graph difference must be detected and reported as a difference, not as text noise.
    right = left;
    right.Gpr[0] = AG_WRITE;           // drop the read that was there
    SelfTestCheck("graph-diff-detected", AgCompare(&left, &right, diff, sizeof(diff)) != 0);

    right = left;
    right.Stack = AG_NONE;             // missing implicit stack effect
    SelfTestCheck("implicit-stack-detected", AgCompare(&left, &right, diff, sizeof(diff)) != 0);

    right = left;
    right.Gpr[4] = AG_WRITE;           // address-only register falsely reported as modified
    SelfTestCheck("spurious-write-detected", AgCompare(&left, &right, diff, sizeof(diff)) != 0);

    right = left;
    right.FlagsModified = 0;           // missing implicit flags write
    SelfTestCheck("flag-detail-detected", AgCompare(&left, &right, diff, sizeof(diff)) != 0);

    // Whitespace normalization must collapse only padding, never operand text.
    NormalizeText("PUSH      rax", normalized, sizeof(normalized));
    SelfTestCheck("normalize-padding", 0 == strcmp(normalized, "PUSH rax"));

    NormalizeText("MOV  eax,  dword ptr [rbx+rcx*2]  ", normalized, sizeof(normalized));
    SelfTestCheck("normalize-inner", 0 == strcmp(normalized, "MOV eax, dword ptr [rbx+rcx*2]"));

    // And the text comparator must classify exactly those two situations differently.
#ifndef BDDISASM_NO_FORMAT
    {
        INSTRUX instrux;

        memset(&instrux, 0, sizeof(instrux));
        if (NdDecodeEx(&instrux, (const uint8_t *)"\x50", 1, ND_CODE_64, ND_DATA_64) == ND_STATUS_SUCCESS &&
            NdToText(&instrux, 0, sizeof(text), text) == ND_STATUS_SUCCESS)
        {
            char baseline[512];
            char cosmetic[512];

            // The baseline is whatever the decoder prints, so a padding change can never make the
            // self-test fail by itself; only the classification of the variant matters.
            snprintf(baseline, sizeof(baseline), "%s", text);
            snprintf(cosmetic, sizeof(cosmetic), "%s", text);
            strncat(cosmetic, "   ", sizeof(cosmetic) - strlen(cosmetic) - 1);

            SelfTestCheck("text-identical",
                          CheckText(&instrux, baseline, text, sizeof(text)) == VERDICT_PASS);
            SelfTestCheck("text-trailing-space-is-cosmetic",
                          CheckText(&instrux, cosmetic, text, sizeof(text)) == VERDICT_WARN_TEXT_FORMAT);
            SelfTestCheck("text-operand-change",
                          CheckText(&instrux, "PUSH\tTEXT-DIFFERS", text, sizeof(text)) == VERDICT_FAIL_TEXT);
        }
        else
        {
            SelfTestCheck("text-decode", 0);
        }
    }
#endif

    // A bad expectation string must be rejected instead of silently zero-initialized.
    SelfTestCheck("bad-access-rejected",
                  AgParseExpected("mem=Q", &other, err, sizeof(err)) != 0);
    SelfTestCheck("bad-field-rejected",
                  AgParseExpected("nonsense=R", &other, err, sizeof(err)) != 0);
    SelfTestCheck("bad-register-rejected",
                  AgParseExpected("gpr:notareg=R", &other, err, sizeof(err)) != 0);

    if (0 == gSelfTestFailures)
    {
        printf("PASS  harness self-tests (comparator, parser, text classifier)\n");
    }
}

//
// ---------------------------------------------------------------------------------------------
// Sweep: run the invariant checks over a compact grid of opcodes, prefixes and modrm forms, and
// group findings by mnemonic + invariant so that a systemic problem is reported once, with a
// minimal reproducible encoding.
// ---------------------------------------------------------------------------------------------
typedef struct _SWEEP_FINDING
{
    char            Key[96];
    char            Bytes[64];
    uint8_t         Mode;
    ND_INS_CLASS    Instruction;
    const char      *Invariant;
    char            Detail[160];
    int             Count;
} SWEEP_FINDING;

#define MAX_FINDINGS 64

static SWEEP_FINDING gFindings[MAX_FINDINGS];
static int gFindingCount;

static void
SweepRecord(
    const char *Invariant,
    const INSTRUX *Instrux,
    const uint8_t *Bytes,
    unsigned Length,
    uint8_t Mode,
    const char *Detail
)
{
    char key[96];
    char hex[64];
    unsigned i;
    int f;

#ifdef BDDISASM_NO_MNEMONIC
    snprintf(key, sizeof(key), "%s/class-%u", Invariant, (unsigned)Instrux->Instruction);
#else
    snprintf(key, sizeof(key), "%s/%s", Invariant, Instrux->Mnemonic ? Instrux->Mnemonic : "?");
#endif

    for (f = 0; f < gFindingCount; f++)
    {
        if (0 == strcmp(gFindings[f].Key, key))
        {
            gFindings[f].Count++;
            return;
        }
    }

    if (gFindingCount >= MAX_FINDINGS)
    {
        return;
    }

    hex[0] = 0;
    for (i = 0; i < Length; i++)
    {
        char one[8];
        snprintf(one, sizeof(one), "%02X", Bytes[i]);
        strcat(hex, one);
    }

    snprintf(gFindings[gFindingCount].Key, sizeof(gFindings[gFindingCount].Key), "%s", key);
    snprintf(gFindings[gFindingCount].Detail, sizeof(gFindings[gFindingCount].Detail), "%s", Detail);
    snprintf(gFindings[gFindingCount].Bytes, sizeof(gFindings[gFindingCount].Bytes), "%s", hex);
    gFindings[gFindingCount].Mode = Mode;
    gFindings[gFindingCount].Instruction = Instrux->Instruction;
    gFindings[gFindingCount].Invariant = Invariant;
    gFindings[gFindingCount].Count = 1;
    gFindingCount++;
}

static void
SweepOne(
    const uint8_t *Bytes,
    unsigned Length,
    uint8_t Mode
)
{
    INSTRUX instrux;
    AG_GRAPH operandView;
    AG_GRAPH mapView;
    char detail[192];
    const char *invariant;

    memset(&instrux, 0, sizeof(instrux));

    if (NdDecodeEx(&instrux, Bytes, Length, Mode,
                   Mode == ND_CODE_64 ? ND_DATA_64 :
                   (Mode == ND_CODE_32 ? ND_DATA_32 : ND_DATA_16)) != ND_STATUS_SUCCESS)
    {
        return;
    }

    if (AgBuildMapView(&instrux, &mapView) != ND_STATUS_SUCCESS)
    {
        SweepRecord("access-map-failure", &instrux, Bytes, instrux.Length, Mode, "");
        return;
    }

    mapView.Cs = (uint8_t)instrux.CsAccess;
    AgBuildOperandView(&instrux, &operandView);

    detail[0] = 0;
    invariant = CheckInvariants(&instrux, &operandView, &mapView, detail, sizeof(detail));
    if (NULL != invariant)
    {
        SweepRecord(invariant, &instrux, Bytes, instrux.Length, Mode, detail);
    }
}

static void
RunSweep(void)
{
    static const uint8_t tails[][6] =
    {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x04, 0x24, 0x00, 0x00, 0x00, 0x00 },
        { 0x04, 0x25, 0x00, 0x00, 0x00, 0x00 },
        { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 },
    };
    static const unsigned tailSizes[] = { 0, 1, 2, 4, 5 };
    static const uint8_t prefixes[] = { 0x66, 0x67, 0xF2, 0xF3, 0x48 };
    static const uint8_t coreOps[] =
    {
        0x50, 0x58, 0x60, 0x61, 0x6A, 0x8B, 0x89, 0x8D, 0x8F, 0xFF, 0xFE, 0xF6, 0xF7,
        0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0x9C, 0x9D, 0xC2,
        0xC3, 0xC8, 0xC9, 0xCB, 0xE0, 0xE1, 0xE2, 0xE8, 0x74, 0xCC, 0xCD, 0xCF, 0xD7,
        0xE4, 0xEC, 0xEE,
    };
    // VEX-encoded bank instructions, which no legacy/0F grid reaches.
    static const uint8_t vexBankCases[][3] =
    {
        { 0xC5, 0xFC, 0x77 },   // VZEROALL
        { 0xC5, 0xF8, 0x77 },   // VZEROUPPER
    };
    uint8_t buffer[16];
    uint8_t mode;
    unsigned p, o, t, v;

    gFindingCount = 0;

    for (mode = 0; mode < 3; mode++)
    {
        for (v = 0; v < sizeof(vexBankCases) / sizeof(vexBankCases[0]); v++)
        {
            memcpy(buffer, vexBankCases[v], 3);
            SweepOne(buffer, 3, mode);
        }

        // One-byte opcodes.
        for (o = 0; o < 256; o++)
        {
            memset(buffer, 0x90, sizeof(buffer));
            buffer[0] = (uint8_t)o;
            SweepOne(buffer, 1, mode);
        }

        // 0F two-byte opcodes: modrm.reg selects a different instruction for the 0F 01 / 0F AE /
        // 0F C7 groups, so sweep every reg value in both register and memory form.
        for (o = 0; o < 256; o++)
        {
            unsigned reg;

            for (reg = 0; reg < 8; reg++)
            {
                memset(buffer, 0x90, sizeof(buffer));
                buffer[0] = 0x0F;
                buffer[1] = (uint8_t)o;
                buffer[2] = (uint8_t)(0xC0 | (reg << 3));
                SweepOne(buffer, 3, mode);

                memset(buffer, 0x90, sizeof(buffer));
                buffer[0] = 0x0F;
                buffer[1] = (uint8_t)o;
                buffer[2] = (uint8_t)(reg << 3);
                SweepOne(buffer, 3, mode);
            }
        }

        // Prefix x opcode x addressing-form grid.
        for (p = 0; p < sizeof(prefixes); p++)
        {
            for (o = 0; o < sizeof(coreOps); o++)
            {
                for (t = 0; t < sizeof(tailSizes) / sizeof(tailSizes[0]); t++)
                {
                    unsigned length = 2 + tailSizes[t];

                    memset(buffer, 0x90, sizeof(buffer));
                    buffer[0] = prefixes[p];
                    buffer[1] = coreOps[o];
                    memcpy(buffer + 2, tails[t], tailSizes[t]);
                    SweepOne(buffer, length, mode);
                }

                memset(buffer, 0x90, sizeof(buffer));
                buffer[0] = prefixes[p];
                buffer[1] = 0x0F;
                buffer[2] = 0x44;
                buffer[3] = 0xC0;
                SweepOne(buffer, 4, mode);

                memset(buffer, 0x90, sizeof(buffer));
                buffer[0] = prefixes[p];
                buffer[1] = 0x0F;
                buffer[2] = 0x94;
                buffer[3] = 0x00;
                SweepOne(buffer, 4, mode);
            }
        }
    }
}

//
// Known deviations, keyed by instruction class rather than by mnemonic, so this stays valid in a
// BDDISASM_NO_MNEMONIC build. Each entry documents a defect that the sample table also covers;
// the sweep is the exhaustive check that no other instruction is affected.
//
static int
IsKnownSweepFinding(
    const SWEEP_FINDING *Finding
)
{
    ND_INS_CLASS ins = Finding->Instruction;

    if (0 == strcmp(Finding->Invariant, "flags-write-not-aggregated"))
    {
        // CMPS writes the arithmetic flags, but only advertises a flags read.
        return ND_INS_CMPS == ins;
    }

    if (0 == strcmp(Finding->Invariant, "flags-read-not-aggregated"))
    {
        // INT/INT3/INTO/INT1 test VM; FCMOVcc tests one of the C0-C3 aliases.
        return ND_INS_INT == ins || ND_INS_INT3 == ins || ND_INS_INTO == ins ||
               ND_INS_INT1 == ins || ND_INS_FCMOVB == ins || ND_INS_FCMOVBE == ins ||
               ND_INS_FCMOVE == ins || ND_INS_FCMOVNB == ins || ND_INS_FCMOVNBE == ins ||
               ND_INS_FCMOVNE == ins || ND_INS_FCMOVNU == ins || ND_INS_FCMOVU == ins;
    }

    if (0 == strcmp(Finding->Invariant, "block-operand-count"))
    {
        // PUSHA/POPA describe a block register with Count=1, exposing only AX.
        return ND_INS_PUSHA == ins || ND_INS_POPA == ins;
    }

    if (0 == strcmp(Finding->Invariant, "unresolved-register-bank"))
    {
        // A bank operand that NdGetFullAccessMap cannot expand to any register.
        return ND_INS_PUSHAD == ins || ND_INS_POPAD == ins ||
               ND_INS_VZEROALL == ins || ND_INS_VZEROUPPER == ins ||
               ND_INS_FXSAVE == ins || ND_INS_FXSAVE64 == ins ||
               ND_INS_FXRSTOR == ins || ND_INS_FXRSTOR64 == ins;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int pass = 0, fail = 0, deviation = 0, fixed = 0, warn = 0;
    char detail[256];
    int i;
    int unexpectedSweep = 0, knownSweep = 0;

    RunSelfTests();
    if (gSelfTestFailures)
    {
        printf("%d harness self-test(s) failed; aborting before scoring samples\n",
               gSelfTestFailures);
        return 1;
    }

    printf("\n== access-graph samples ==\n");

    for (i = 0; i < SAMPLE_COUNT; i++)
    {
        const SAMPLE *sample = &gSamples[i];
        VERDICT verdict = RunSample(sample, detail, sizeof(detail));

        // A sample that documents a known defect must keep failing for that documented reason.
        // If it starts passing, the note is stale and the run fails, so the expectation is either
        // promoted or the documentation corrected - a silent "green" cannot hide a fix.
        if (VERDICT_PASS == verdict && NULL != sample->Deviation)
        {
            verdict = VERDICT_FIXED;
        }
        else if (NULL != sample->Deviation && VERDICT_FAIL_TEXT != verdict &&
                 VERDICT_WARN_TEXT_FORMAT != verdict)
        {
            // The expectation is architectural truth and the decoder does not meet it yet. Text
            // problems on such a sample are never excused.
            verdict = VERDICT_KNOWN_DEVIATION;
        }

        switch (verdict)
        {
        case VERDICT_PASS:
            pass++;
            printf("PASS  %-24s %s\n", sample->Name, sample->Why);
            break;
        case VERDICT_WARN_TEXT_FORMAT:
            warn++;
            printf("WARN  %-24s text-format-only: %s\n", sample->Name, detail);
            break;
        case VERDICT_KNOWN_DEVIATION:
            deviation++;
            printf("DEV   %-24s %s\n", sample->Name, sample->Deviation);
            printf("        bytes=");
            PrintBytes(sample);
            printf(" mode=%u  difference: %s\n", sample->Mode, detail);
            break;
        case VERDICT_FIXED:
            fixed++;
            printf("FIXED %-24s expected deviation is gone, remove the Deviation note\n",
                   sample->Name);
            break;
        case VERDICT_FAIL_OPERAND_GRAPH:
        case VERDICT_FAIL_MAP_GRAPH:
        case VERDICT_FAIL_INVARIANT:
        case VERDICT_FAIL_TEXT:
            fail++;
            printf("FAIL  %-24s %s\n", sample->Name, VerdictName(verdict));
            printf("        bytes=");
            PrintBytes(sample);
            printf(" mode=%u  %s\n", sample->Mode, detail);
            printf("        expected: %s\n", sample->Expected);
            break;
        }

        (void)warn;
    }

    printf("\n== invariant sweep over opcode space ==\n");

    RunSweep();

    for (i = 0; i < gFindingCount; i++)
    {
        SWEEP_FINDING *finding = &gFindings[i];

        if (IsKnownSweepFinding(finding))
        {
            knownSweep++;
            printf("DEV   %-40s mode=%u bytes=%s  (%d encodings)  %s\n",
                   finding->Key, finding->Mode, finding->Bytes, finding->Count,
                   finding->Detail);
        }
        else
        {
            unexpectedSweep++;
            printf("FAIL  %-40s mode=%u bytes=%s  (%d encodings)  %s\n",
                   finding->Key, finding->Mode, finding->Bytes, finding->Count,
                   finding->Detail);
        }
    }

    printf("\n== summary ==\n");
    printf("samples: %d passed, %d failed, %d known-deviation, %d text-format-only, %d fixed\n",
           pass, fail, deviation, warn, fixed);
    printf("sweep  : %d known-deviation groups, %d unexpected groups\n",
           knownSweep, unexpectedSweep);

    return (fail == 0 && unexpectedSweep == 0 && fixed == 0 && gSelfTestFailures == 0) ? 0 : 1;
}
