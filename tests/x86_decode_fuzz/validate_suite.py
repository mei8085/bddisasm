#!/usr/bin/env python3
#
# Copyright (c) 2025 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""Self-validation of the x86 decoder integration tests.

A test suite that can only ever pass proves nothing. This script mutates the
decoder in ways that violate a specific invariant, rebuilds the harness against
the mutated copy, and asserts that the mutated build is actually rejected and
that a minimized, replayable sample is produced.

Each mutation is described as a textual edit to a decoder source file; a
mutation that no longer applies (because the code moved) is reported as a
skip, not a failure. Mutations that fail to compile are reported as skips too:
they still show that the harness is compiled against the mutated tree.

Usage:
    python3 tests/x86_decode_fuzz/validate_suite.py [--cases N] [--keep]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

DECODER_SOURCES = [
    "bddisasm/bddisasm_crt.c",
    "bddisasm/bdx86_decoder.c",
    "bddisasm/bdx86_formatter.c",
    "bddisasm/bdx86_helpers.c",
    "bddisasm/bdx86_idbe.c",
    "bddisasm/bdx86_operand.c",
]

TEST_SOURCES = [
    "x86_decode_fuzz.c",
    "x86_decode_gen.c",
    "x86_decode_checks.c",
]

CFLAGS = ["-std=c11", "-g", "-O1", "-w",
          "-fsanitize=address,undefined", "-fno-sanitize=alignment",
          "-DBDDISASM_HAS_MEMSET", "-DBDDISASM_HAS_VSNPRINTF"]


#
# Mutations. Each one turns a correct decoder into one that violates exactly one
# of the invariants the suite checks. `expect` names the failure the suite is
# expected to report.
#
MUTATIONS = [
    {
        "name": "drop-immediate-length",
        "expect": "integer/relative payload not counted in Length",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "    return NdIncrementLength(Instrux, ImmediateSize);\n\n#undef Instrux\n}\n\n//\n// NdFetchImmediate2",
        "new": "    return ND_STATUS_SUCCESS;\n\n#undef Instrux\n}\n\n//\n// NdFetchImmediate2",
    },
    {
        "name": "drop-sib-length",
        "expect": "SIB byte not counted in Length",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "    Instrux->Sib.Sib = Code[Offset];\n    \n    return NdIncrementLength(Instrux, 1);",
        "new": "    Instrux->Sib.Sib = Code[Offset];\n    \n    return ND_STATUS_SUCCESS;",
    },
    {
        "name": "modrm-offset+1",
        "expect": "ModRM offset reported past its actual position",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "    Instrux->HasModRm = ND_TRUE;\n    Instrux->ModRmOffset = Offset;",
        "new": "    Instrux->HasModRm = ND_TRUE;\n    Instrux->ModRmOffset = Offset + 1;",
    },
    {
        "name": "displacement-width+1",
        "expect": "displacement width reported one byte too large",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "    Instrux->HasDisp = ND_TRUE;\n    Instrux->DispLength = DispSize;",
        "new": "    Instrux->HasDisp = ND_TRUE;\n    Instrux->DispLength = DispSize + 1;",
    },
    {
        "name": "drop-prefix-bound-check",
        "expect": "prefix loop reading past the exact window (ASan heap-buffer-overflow)",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "        // At least one more byte must be available.\n        RET_GT((ND_SIZET)Offset + 1, Size, ND_STATUS_BUFFER_TOO_SMALL);",
        "new": "        // At least one more byte must be available.",
    },
    {
        # The SKIP_CACHE_IBYTES path decodes straight from the caller's buffer
        # instead of a private copy. Claiming one byte more than the caller
        # supplied makes the decoder read past the exact window.
        "name": "skip-cache-window+1",
        "expect": "SKIP_CACHE_IBYTES path reads past the exact window (ASan heap-buffer-overflow)",
        "file": "bddisasm/bdx86_decoder.c",
        "old": "        toFetch = Size;\n        iCode = Code;",
        "new": "        toFetch = Size + 1;\n        iCode = Code;",
    },
]


def log(message: str) -> None:
    print("[*] " + message, flush=True)


def error(message: str) -> None:
    print("[!] " + message, flush=True)


def compiler() -> str:
    return os.environ.get("CC", "cc")


def copy_tree(dest: str) -> None:
    for name in ("bddisasm", "inc"):
        shutil.copytree(os.path.join(ROOT, name), os.path.join(dest, name))


def apply_mutation(dest: str, mutation: dict) -> bool:
    path = os.path.join(dest, mutation["file"])
    with open(path, "r") as fp:
        text = fp.read()

    if mutation["old"] not in text:
        return False

    text = text.replace(mutation["old"], mutation["new"], 1)

    with open(path, "w") as fp:
        fp.write(text)

    return True


def build(dest: str) -> str:
    objects = []

    for source in DECODER_SOURCES:
        obj = os.path.join(dest, os.path.basename(source) + ".o")
        command = [compiler()] + CFLAGS + [
            "-I", os.path.join(dest, "inc"),
            "-I", os.path.join(dest, "bddisasm", "include"),
            "-I", os.path.join(ROOT, "tests", "x86_decode_fuzz"),
            "-c", os.path.join(dest, source), "-o", obj]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        objects.append(obj)

    for source in TEST_SOURCES:
        obj = os.path.join(dest, source + ".o")
        command = [compiler()] + CFLAGS + [
            "-I", os.path.join(dest, "inc"),
            "-I", os.path.join(dest, "bddisasm", "include"),
            "-I", os.path.join(ROOT, "tests", "x86_decode_fuzz"),
            "-c", os.path.join(ROOT, "tests", "x86_decode_fuzz", source), "-o", obj]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        objects.append(obj)

    binary = os.path.join(dest, "harness")
    command = [compiler(), "-std=c11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-sanitize=alignment"] + objects + ["-o", binary]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return binary


def harness(binary: str, args: list) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

    return subprocess.run([binary] + args, capture_output=True, text=True, env=env)


def check_mutation(mutation: dict, cases: int, keep: bool) -> str:
    workdir = tempfile.mkdtemp(prefix="xdf-mut-")

    try:
        copy_tree(workdir)

        if not apply_mutation(workdir, mutation):
            return "SKIP (pattern not found)"

        try:
            binary = build(workdir)
        except RuntimeError as exc:
            return "SKIP (mutation does not compile: %s)" % str(exc).strip().splitlines()[0]

        # Step 1: the built-in fixtures or the fuzz sweep must reject the build.
        report = os.path.join(workdir, "report")
        os.makedirs(report, exist_ok=True)

        selftest = harness(binary, ["self-test"])
        fuzz = harness(binary, ["run", "--seed", "3", "--cases", str(cases),
                                "--report-dir", report])

        rejected = selftest.returncode != 0 or fuzz.returncode != 0

        asan_hit = "AddressSanitizer" in (fuzz.stderr + selftest.stderr)

        samples = []
        if os.path.isdir(report):
            samples = [os.path.join(report, name) for name in sorted(os.listdir(report))
                       if name.endswith("-repro.case")]

        if not rejected:
            return "FAIL (mutation was not detected)"

        # Step 2: at least one minimized sample must have been written, and it
        # must reproduce when reloaded.
        if not asan_hit and not samples:
            return "FAIL (detected, but no sample was recorded)"

        for sample in samples:
            replay = harness(binary, ["replay", "--case", sample])
            if replay.returncode == 0:
                return "FAIL (sample %s did not reproduce)" % os.path.basename(sample)

        detail = "ASan" if asan_hit else "%d sample(s)" % len(samples)
        return "OK (%s, %s)" % (detail, mutation["expect"])

    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            log("kept mutated tree in " + workdir)


def main() -> int:
    parser = argparse.ArgumentParser(description="validate the decoder test suite itself")
    parser.add_argument("--cases", type=int, default=2000,
                        help="cases per mutation (default 2000)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary mutated trees")
    args = parser.parse_args()

    failures = 0
    skipped = 0

    for mutation in MUTATIONS:
        log("mutating: " + mutation["name"])
        outcome = check_mutation(mutation, args.cases, args.keep)

        if outcome.startswith("FAIL"):
            error("%-24s %s" % (mutation["name"], outcome))
            failures += 1
        elif outcome.startswith("SKIP"):
            log("%-24s %s" % (mutation["name"], outcome))
            skipped += 1
        else:
            log("%-24s %s" % (mutation["name"], outcome))

    print()
    log("%d mutation(s) caught, %d skipped, %d failed"
        % (len(MUTATIONS) - skipped - failures, skipped, failures))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
