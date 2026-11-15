# Operand access-graph tests

These tests check what a decoded instruction **reads and writes**, not how it is printed. That
matters for anything that follows data flow: emulators, taint trackers, decompilers, and
instruction-level dependency analysis all consume the per-operand access bits, the implicit
operands and `NdGetFullAccessMap`, and a single missing implicit write silently truncates the
graph.

Each sample is a minimal machine-code sequence with an explicit, hand-written expectation of:

* explicit operand accesses (read / write / conditional read / conditional write / prefetch),
* implicit accesses that are not spelled out as operands (stack pointer updates, segment reads,
  addressing registers, RIP, RFLAGS, shadow stack, `SSP`),
* per-bit flag detail (`Tested` / `Modified` / `Set` / `Cleared` / `Undefined`), and
* the number of stack words moved.

Every expectation is checked against **two independent views** of the same instruction:

1. the read/write set rebuilt from `INSTRUX.Operands`, applying the documented implicit effects;
2. the set reported by `NdGetFullAccessMap`.

A disagreement between the two views is itself a failure, because consumers are entitled to use
either one.

## Why the graph and the text are kept apart

Textual disassembly is checked last and in its own bucket, with a whitespace-normalized
comparison in between. A change in column padding is reported as `WARN (text-format-only)` and
never fails the run; a change in the printed operands is reported as `FAIL (text)`. A graph
problem is reported as `FAIL (operand-graph)` or `FAIL (map-graph)`, so a formatting change can
never be mistaken for a data-flow regression and vice versa.

## Access rules encoded by the harness

The expectation strings encode the rules that matter for data-flow tracking:

* Any stack memory access (`IsStack`) reads and writes RSP and reads SS. This is implicit for
  `push`/`pop`/`call`/`ret`/`leave`/`enter` and even for `push imm`, which has no register
  operand at all.
* A plain memory operand reads its segment, its base register and its index register, but never
  writes them.
* An address-generation operand (`LEA`, `IsAG`) reads base/index and performs **no** memory
  access. Reporting the base or index as modified is a bug, and the sweep checks for it.
* RIP-relative addressing reads the segment but no GPR; RIP itself is only touched by control
  transfer.
* String instructions read/write RSI/RDI and the direction flag; with `REP`/`REPE`/`REPNE` every
  access becomes conditional and RCX becomes read-conditional-write.
* Conditional instructions use `CW` (conditional write) for the destination and `ft=` for the
  tested flag bits: `CMOVcc`, `SETcc` (unconditional write), `CMPXCHG`, `Jcc`, `LOOP`.
* Shadow stack accesses are tracked separately (`shadow=`) because `NdGetFullAccessMap` folds them
  into `MemAccess`.

## Expectation syntax

```
field=acc;field=acc;bank:reg=acc,reg=acc;ft=0x40;fm=0x8d5;sw=2
```

Scalar fields: `mem`, `shadow`, `stack`, `rfl`, `rip`, `cs`, `ssp`, `mxcsr`, `pkru`, `uif`.
Flag detail: `ft` (tested), `fm` (modified), `fs` (set), `fc` (cleared), `fu` (undefined).
Stack words: `sw`.

Register banks: `gpr`, `seg`, `fpu`, `mmx`, `sse`, `cr`, `dr`, `tr`, `bnd`, `msk`, `tmm`, `sys`,
`x87`. Register names: `rax`..`r31`, `es`..`gs`, `st0`..`st7`, `mm0`..`mm7`, `xmm0`..`xmm31`,
`cr0`.., `dr0`.., `tr0`.., `bnd0`.., `k0`..`k7`, `tmm0`.., `gdtr`/`idtr`/`ldtr`/`tr`.

Access letters: `R`, `W`, `CR` (conditional read), `CW` (conditional write), `P` (prefetch), or
`-` for none.

## Running

```
./tests/access/run_tests.sh                       # auto-detects libbddisasm.a
./tests/access/run_tests.sh path/to/libbddisasm.a # explicit
BDDISASM_LIB=... ./tests/access/run_tests.sh
```

The script builds `access_graph.c` + `access_graph_test.c` against the static library and runs
them. It only needs a C11 compiler and the library; it does not need `disasmtool`, `nasm` or the
Python test harness. In CMake, configure with `-DBDD_INCLUDE_TESTS=ON` and the
`access_graph_test` executable is built and run from the `test` target.

Exit code is 0 when every sample passes, the harness self-tests pass, and the opcode sweep finds
no *unexpected* structural violation.

## Output categories

| Marker  | Meaning |
|---------|---------|
| `PASS`  | Expected graph, both views and text all agree. |
| `WARN`  | Text differs only in whitespace/padding. Cosmetic; does not fail the run. |
| `FAIL`  | Graph, invariant or text mismatch. The encoding and the first differing field are printed. |
| `DEV`   | A known deviation: the sample documents architecturally expected behaviour that the decoder does not currently produce. Reported, does not fail the run. |
| `FIXED` | A `DEV` sample now passes. This fails the run so the stale note gets removed. |

Known deviations are pinned by instruction class, not by mnemonic, so the same table works in a
`BDD_NO_MNEMONIC` build.

## Harness self-tests

Before scoring any sample the harness proves its own comparator works: parse→print→parse round
trip, detection of a removed read, a removed implicit stack effect, a spurious write, a missing
flag write, and the three text classifications. A comparator that always returned "equal" would
otherwise make the whole suite vacuously green.

## Invariant sweep

On top of the named samples, the harness sweeps a byte grid (one-byte opcodes, `0F` two-byte
opcodes across all `modrm.reg` values in register and memory form, a prefix × opcode ×
addressing-form grid, and the VEX bank instructions) in 16/32/64-bit modes and checks invariants
that must hold for *every* instruction:

* `stack-access-disagreement` - the aggregate `StackAccess`, the operand-derived stack set and
  the map must agree.
* `memory-access-disagreement` / `memory-map-disagreement` - `INSTRUX.MemoryAccess` must be the
  same set as the memory operands (stack + plain + shadow stack).
* `map-drops-register-access` - every register the operands imply must be in the map.
* `unjustified-gpr-write` - a GPR write in the map must be backed by a register operand or the
  implicit stack pointer update. This is what catches address-only registers being reported as
  modified.
* `block-operand-count` - a block register operand must describe more than one register.
* `unresolved-register-bank` - a bank operand must contribute at least one register access that
  the ordinary operands do not already account for.
* `flags-write-not-aggregated` / `flags-read-not-aggregated` - the per-bit flag detail must not
  contradict the aggregate RFLAGS access.
* `sys-slot-aliasing` - an x87 instruction must not report a `ND_REG_SYS` slot shared with
  GDTR/IDTR/LDTR. Reported by the sample check rather than the sweep: the sweep's `0F` grid does
  not reach x87 encodings, and the aliasing is unambiguous per instruction.
* `stack-words-mismatch` - a stack access and a non-zero `StackWords` must come together.

Findings are grouped by invariant + instruction and printed once, with the minimal reproducible
encoding and the number of encodings affected. Groups that correspond to a documented deviation
are reported as `DEV`; anything else is `FAIL` and fails the run.

## Known deviations found by this suite

These are reported as `DEV` with a minimal encoding; the sweep confirms no other instruction is
affected.

1. **`PUSHAD`/`POPAD` do not expand their register bank.** The bank operand has no register
   identity, and `NdGetFullAccessMap` expands only `FNSAVE`/`FRSTOR` and the `XSAVE` family, so
   the eight GPRs pushed or restored are missing from both views (`60`, `61` in 32-bit mode).
2. **`PUSHA`/`POPA` expose a block register with `Count = 1`.** Only AX is reported; the other
   seven GPRs missing from the graph (`60`, `61` in 16-bit mode).
3. **`FXSAVE`/`FXRSTOR`/`VZEROALL`/`VZEROUPPER` banks are not expanded.** The x87/SSE state the
   instruction saves, restores or zeroes is absent from the map (`0F AE /0`, `0F AE /1`, `C5 FC 77`,
   `C5 F8 77`).
4. **`CMPS` reports `RflAccess = read` while it writes the arithmetic flags.** `FlagsAccess`
   says CF/PF/AF/ZF/SF/OF are modified, but the aggregate says read-only, so the map hides the
   write. `SCAS`, which uses the same flag template, is correct (`A6`, `A7`, `48 A7`).
5. **`INT`/`INT3`/`INTO`/`INT1` report `RflAccess = write` while they test VM.** The per-bit
   `Tested` set names VM, but the aggregate has no read bit (`CC`, `CD`, `CE`, `F1`).
6. **`FCMOVcc` reports `RflAccess = write` while it tests CF/C0.** Same shape as (5) (`DA C1`,
   `DB C1`, ...).
7. **x87 control/tag/status words alias the descriptor-table `ND_REG_SYS` slots.**
   `X87CONTROL`/`X87TAG`/`X87STATUS` are `ND_REG_SYS` with ids 0/1/2, the same ids as
   `GDTR`/`IDTR`/`LDTR`, so `FLDCW` and `LGDT` both report "sys 0 written" (`D9 28` vs `0F 01 10`).

## Files

| File | Purpose |
|------|---------|
| `access_graph.h`, `access_graph.c` | Canonical graph, both views, expectation parser/printer, comparator. No dependency on formatting. |
| `access_graph_test.c` | Sample table, invariant checks, sweep, self-tests, reporting. |
| `run_tests.sh` | Standalone build + run against a static library. |
