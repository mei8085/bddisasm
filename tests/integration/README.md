# bdshemu integration tests

C-level integration tests that drive `ShemuX86Emulate` through its public API.
Unlike the snapshot-based suite in `bdshemu_test/`, these tests assert on
binary-observable state only (emulation status, RIP, instruction lengths,
instruction counts, raw shellcode bytes and shellcode flags); they never parse
disassembly or trace text and need no assembler.

## Self-modifying code semantics

`bdshemu_selfmodifying_test.c` validates that, in controlled x86 emulation,
bytes written into the emulated shellcode buffer are interpreted by later
instruction fetches:

1. **Write-then-fetch coherence** — a store that rewrites code bytes changes
   how subsequent fetches decode, including stores that land inside an existing
   instruction (overlapping / cross-boundary rewrites). The executed address and
   instruction-length trace is reconstructed by re-running the same image with
   increasing `MaxInstructionsCount`, and a `SHEMU_OPT_BYPASS_SELF_WRITES`
   control run proves the original boundaries survive when the write is
   discarded.
2. **Out-of-bounds vs. legitimate self-writes** — stores fully outside, or
   straddling the end of, the shellcode buffer abort with
   `SHEMU_ABORT_GLA_OUTSIDE` without modifying the image; an out-of-range
   control-flow transfer aborts with `SHEMU_ABORT_RIP_OUTSIDE`. In every case
   the executed instructions and the stop reason remain traceable.

All emulated accesses are confined to buffers allocated by the test
(shellcode, virtual stack, internal bitmap). The external-memory callback
refuses every access, so the samples never touch host/process memory.

## Building and running

```sh
make test     # builds (and, if needed, builds the static libraries) and runs
make          # builds the test binary only
make clean
```

The test prints one line per scenario plus `N checks, 0 failures` and exits
non-zero on any failed check.
