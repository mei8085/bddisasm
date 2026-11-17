# Decode-to-text boundary tests

These tests pin down the boundary between **decoding** an instruction and **rendering it as text**. The
subject is untrusted machine code and, just as importantly, an untrusted `INSTRUX`: anything that reaches
`NdToText` / `NdToTextMini` must either be a complete, faithful description of a decoded instruction, or be
rejected with a status that names the reason and with no text at all.

The suite needs only a C11 compiler and `libbddisasm.a` - no CMake, no `disasmtool`, no Python, no NASM.

## Why this boundary needs its own tests

A decoder that is fed attacker-controlled bytes will eventually fail. The interesting question is what it
leaves behind:

* Does a failed decode still carry a mnemonic, an instruction class or operands from the *previous* decode?
  Anyone who logs "instruction at RIP" from such a structure fabricates a plausible instruction out of
  malformed input.
* Does a truncated output buffer leave "MOV eax, " behind, which reads exactly like a real instruction?
* Does an operand the formatter has no name for get silently dropped, producing `CALL` instead of
  `CALL qword ptr [rax]`?
* Does a too-long prefix run get reported as a short input buffer, hiding the real reason?

Every one of those has been observed in a disassembler at some point. The checks below make each of them a
hard failure.

## What is checked

### 1. Decoder output is either complete or clearly failed (`check_decode_contract`)

For random and crafted byte windows, in all three modes:

* On success: `1 <= Length <= 15`, `Length <= window`, a valid instruction class, a definition (`Idbe`)
  that exists and whose `Instruction` matches, a non-NULL mnemonic, operand counts within
  `ND_MAX_OPERAND`, and `OperandsCount >= ExpOperandsCount`.
* On failure: the identity is cleared (`Instruction == ND_INS_INVALID`, `Idbe == 0`, both operand counts
  zero), no mnemonic, and `Length <= window`. `Length` is still meaningful as the boundary the decoder
  reached, and the status is the reason.

The same is checked after a successful decode followed by a failed one using
`ND_OPTION_SKIP_ZERO_INSTRUX`, which is the case where stale state would otherwise leak.

### 2. Window semantics distinguish "short input" from "too long" (`check_window_semantics`)

* An instruction that needs more bytes than the window reports `ND_STATUS_BUFFER_TOO_SMALL`.
* A prefix run longer than 15 bytes reports `ND_STATUS_INSTRUCTION_TOO_LONG` when the caller supplied a
  16th byte, and never reads beyond 15 bytes.
* The full and mini decoders agree, both with and without `ND_OPTION_SKIP_CACHE_IBYTES`.
* A window larger than 15 bytes decodes a short instruction normally (it is a buffer, not one instruction).

### 3. Formatted text is complete or absent (`check_text_contract`)

For every decoded instruction, format it into buffers of many sizes:

* On success: non-empty text, `strlen(text) < BufferSize`, finished with a NUL.
* On any failure: the status is `ND_STATUS_BUFFER_OVERFLOW` and the buffer is **empty**. A partial render is
  never left behind.

The longest text any instruction in this build can produce is asserted to fit in `ND_MIN_BUF_SIZE`, the size
the documentation recommends for `NdToText`.

### 4. Malformed structures are rejected, not rendered (`check_malformed_rejection`)

Each case starts from a real decoded instruction, breaks exactly one structural invariant, and requires
`NdToText` to return `ND_STATUS_INVALID_INSTRUX` with an empty buffer:

| mutation                                                   | invariant it breaks                       |
|------------------------------------------------------------|-------------------------------------------|
| `Idbe` out of range                                        | instruction definition must exist         |
| `Instruction` set to `ND_INS_INVALID`                       | instruction class must be real            |
| `Length == 0`, `Length > 15`                                | instruction length bounds                 |
| `PrefLength > Length`, `OpOffset + OpLength > Length`       | field layout inside the instruction       |
| `ExpOperandsCount = ND_MAX_OPERAND + 1`                     | operand count inside `Operands[]`         |
| memory operand with `Scale == 3`                            | scale is 1, 2, 4 or 8                     |
| memory operand with `{1to0}` broadcast                      | a broadcast repeats at least twice        |
| explicit `NOT_PRESENT` operand                              | explicit operands are present             |
| 8-bit GPR index 8..15 in a legacy no-REX instruction         | only `al..bh` exist there                  |
| 8-bit register class with no textual name (e.g. an MSR)     | register must be nameable                 |
| immediate operand with `Size == 3`                          | immediates are 1/2/4/8 bytes              |
| constant operand larger than 32 bits                        | constants are small architectural values  |
| RIP-relative memory operand outside 64-bit mode             | RIP-relative addressing is 64-bit only    |

A NULL `INSTRUX` and a zero-sized buffer must be rejected (returning an error, not a crash), and a
one-byte buffer must report truncation with the byte set to NUL.

### 5. Valid instructions are unchanged (`check_golden_text`)

A table of hand-written encodings asserts the exact text, so that hardening the boundary cannot silently
change the language the formatter produces: displacements with both signs, absolute and RIP-relative
addresses, sign-extended immediates, register/segment forms, the operand-less `PUSHF`/`PUSHAD` forms with
their trailing alignment, and the EVEX decorators.

## Running

```sh
# auto-detect libbddisasm.a in the usual build locations
./tests/text_boundary/run_tests.sh

# explicit library and/or compiler
LIBN=path/to/libbddisasm.a CC=clang ./tests/text_boundary/run_tests.sh
```

In CMake, configure with `-DBDD_INCLUDE_TESTS=ON`; the `text_boundary_test` executable is built and run from
the `test` target.

The driver links the static library that the normal build produces. Pass `-DBDD_ASAN=ON -DBDD_UBSAN=ON` when
configuring CMake (or build the library yourself with the same `-fsanitize` flags) so that the *library*
itself is instrumented; passing `-fsanitize=...` to this driver alone only instruments the test file. The
suite is clean under `-fsanitize=address,undefined` on both.

## Exit codes

* `0` - every check held.
* `1` - at least one failure; the encoding and the first differing field are printed.
