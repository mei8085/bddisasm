# x86 Decoder Integration Tests (sanitizer + exact-window)

This directory contains a self-contained integration test for the bddisasm x86
instruction decoder. It is aimed at the boundaries a decoder is most likely to
get wrong when it is fed **untrusted machine code**: legacy prefix runs, the
VEX/EVEX/XOP/REX2 payloads, ModRM/SIB/displacement combinations, immediate and
relative-offset widths, instruction length limits, and 16/32/64-bit decode
modes.

The suite builds the decoder with **AddressSanitizer + UBSan** and hands it an
input window that is **exactly as large as the bytes under test** (every decode
gets its own exact-size heap buffer). Any read past the end of that window is a
hard ASan error rather than a silent over-read into neighbouring memory.

Nothing in this directory needs CMake: `run_x86_decode_tests.py` compiles the
decoder straight from the tree. The optional `CMakeLists.txt` wires the same
harness into CMake/CTest for projects that want it.

## What is checked

For every decodable byte sequence `S` and every truncation `S[0:n]`
(`1 <= n <= len(S)`), decoded in every mode:

1. **Length and window.** On success, `Length` is in `[1, 15]` and never
   exceeds the number of bytes supplied. On failure, nothing is fabricated:
   no mnemonic, no operands, no instruction class, and `Length` never exceeds
   the window.
2. **Field tiling.** Every encoded field the decoder reports — prefix run,
   opcode bytes (including the "opcode is the last byte" 3DNow! form), ModRM,
   SIB, displacement, SSE immediate, immediates, relative offset, moffset and
   far/near address — must lie entirely within `[0, Length)`, must not overlap
   another field, and together must cover every byte exactly once. No holes.
3. **Payload values.** `Immediate1/2`, `RelativeOffset`, `Moffset`,
   `Displacement` and the SSE immediate must equal the little-endian bytes at
   their reported offsets.
4. **Operand consistency.** Immediate operands must have a `RawSize` equal to
   one of the encoded immediate widths (or 1 for the SSE-immediate selector);
   relative-offset operands must match `RelOffsLength`; ModRM and moffset
   memory operands must have a `DispSize` equal to the encoded
   displacement/moffset width; a memory operand may not claim a displacement
   the instruction does not encode; register indices and counts are in range
   for their class; RIP-relative addressing only appears in 64-bit mode.
5. **Window independence.** A decode that succeeds with a window shorter than
   the instruction must produce the identical length/instruction when
   re-decoded with a window of exactly `Length`.
6. **Mini decoder agreement.** `NdDecodeWithContextMini` must agree with the
   full decoder on success/failure and on length, both with the normal cached
   instruction bytes and with `ND_OPTION_SKIP_CACHE_IBYTES`.
7. **Determinism.** Decoding the same bytes twice with the same context must
   produce byte-identical results.

The 16/32/64-bit modes, `ND_VEND_ANY/INTEL/AMD`, `ND_FEAT_ALL/NONE` and
`ND_OPTION_ONLY_EXPLICIT_OPERANDS` are all exercised for each generated case.

## Generating the input

`x86_decode_gen.c` derives every case from `(seed, index)` with a deterministic
xorshift generator, so any failure can be regenerated from the printed seed and
index — no corpus files are required. It emits one family per case:

| family        | what it targets                                              |
|---------------|--------------------------------------------------------------|
| `legacy`      | legacy prefix runs + 1-byte opcodes + ModRM/SIB/disp/imm soup |
| `vex`         | 2- and 3-byte VEX, including illegal legacy-prefix combos     |
| `evex`        | regular, promoted-legacy (map 4), promoted-VEX and APX forms  |
| `xop`         | XOP lead byte, plus the 0x8F/POP boundary                     |
| `modrm`       | every ModRM mod/rm shape, 0x67 overrides, REX                  |
| `immediate`   | opcodes whose payload width is the interesting part            |
| `long`        | prefix chains long enough to exceed the 15-byte limit         |
| `prefix-only` | truncated prefix runs                                         |
| `opcode38`    | 0F 38 / 0F 3A three-byte opcodes                              |
| `rex2`        | REX2/APX in 64-bit mode, and 0xD5/AAD elsewhere                |

## Running

```sh
# full run: build with ASan+UBSan, run fixtures, fuzz 20k cases
python3 tests/x86_decode_fuzz/run_x86_decode_tests.py

# shorter fuzz run, different seed
python3 tests/x86_decode_fuzz/run_x86_decode_tests.py --cases 5000 --seed 7

# re-check previously recorded failure samples without fuzzing
python3 tests/x86_decode_fuzz/run_x86_decode_tests.py --replay tests/x86_decode_fuzz/out/report
```

The driver builds the decoder sources directly from the tree, so it needs only
a C compiler (`cc` by default; override with `CC=...`). No CMake is required.

The harness can also be driven directly once built:

```sh
out/bin/x86_decode_fuzz self-test                       # 38 built-in fixtures
out/bin/x86_decode_fuzz run --seed 1 --cases 20000 --mode 64 --report-dir out/report
out/bin/x86_decode_fuzz regen --seed 1 --index 1234     # print a generated case
out/bin/x86_decode_fuzz replay --case out/report/foo-1-4-repro.case
out/bin/x86_decode_fuzz list-ops
```

## Failure samples

Any invariant violation is written to the report directory as three files
named `<family>-<mode>-<window>-{case.bin,desc.txt,repro.case}`. The
`repro.case` file is a self-describing text reproducer:

```
# xdf-repro v1
tag=modrm
mode=32
len=4
window=4
reason=layout: field 'displacement' [3,4) outside instruction length 3
bytes=8d447dde
```

Before being written, each sample is **minimized** to the shortest prefix of
the bytes that still reproduces the failure, and `replay --case FILE` reloads
it, re-runs every check and exits non-zero if the failure is reproducible. This
is what `--replay DIR` does for a whole directory.

## Validating the suite itself

A suite that can only ever pass proves nothing. `validate_suite.py` injects
mutations into a copy of the decoder — each one breaking exactly one invariant
(an immediate/SIB byte dropped from `Length`, a field offset shifted, a
displacement width inflated, a bounds check removed so the exact window is
over-read, the `SKIP_CACHE_IBYTES` path told the buffer is one byte longer than
it is) — rebuilds the harness against the mutated tree and asserts that:

* the mutated build is rejected (fixtures or fuzz run fail, or ASan fires), and
* at least one minimized sample is written and reproduces on replay.

```sh
python3 tests/x86_decode_fuzz/validate_suite.py
```

A mutation whose source pattern no longer matches is reported as skipped, not
as a failure, so the script survives the decoder being refactored.

## Exit codes

* `0` — every invariant held.
* `1` — at least one failure, with samples recorded.
* `2` — build or usage problem.
