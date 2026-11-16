#!/usr/bin/env python3
#
# Copyright (c) 2025 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""Build, run and triage the x86 decoder integration tests.

This driver is intentionally independent of CMake: it compiles the decoder
sources straight from the tree with the sanitizers enabled, runs the harness
and then re-checks every failure sample by reloading it through the harness's
`replay` mode. That makes the whole thing runnable on any Linux box with a C
compiler, and keeps the failure samples reproducible and reloadable.

Usage:
    python3 run_x86_decode_tests.py                # build + self-test + fuzz
    python3 run_x86_decode_tests.py --cases 5000   # shorter fuzz run
    python3 run_x86_decode_tests.py --replay DIR   # replay recorded samples
    python3 run_x86_decode_tests.py --no-build     # reuse an existing binary

Exit codes: 0 all good, 1 test failure, 2 harness/build problem.
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
    "tests/x86_decode_fuzz/x86_decode_fuzz.c",
    "tests/x86_decode_fuzz/x86_decode_gen.c",
    "tests/x86_decode_fuzz/x86_decode_checks.c",
]

# The decoder is built with ASAN so that any read past the exact input window
# we hand it is a hard error, and with UBSAN so undefined arithmetic/shifts in
# the field decoding are caught too. Alignment checking is disabled because the
# decoder deliberately does unaligned loads from the instruction bytes.
SANITIZERS = ["-fsanitize=address,undefined", "-fno-sanitize=alignment"]

DEFINES = [
    "-DBDDISASM_HAS_MEMSET",
    "-DBDDISASM_HAS_VSNPRINTF",
]

# The decoder sources carry some long-standing warnings; do not fail the test
# build on those, but keep our own test sources warning-clean.
DECODER_CFLAGS = ["-Wno-incompatible-pointer-types", "-Wno-unknown-pragmas",
                  "-Wno-unused-function", "-Wno-multichar"]

TEST_CFLAGS = ["-Wall", "-Wextra", "-Wno-unused-parameter", "-Werror"]

BASE_CFLAGS = ["-std=c11", "-g", "-O1", "-fno-omit-frame-pointer"]


def log(message: str) -> None:
    print("[*] " + message, flush=True)


def error(message: str) -> None:
    print("[!] " + message, flush=True)


def compiler() -> str:
    return os.environ.get("CC", "cc")


def build(binary: str, keep: bool = False) -> int:
    """Compile the harness + decoder with ASAN/UBSAN into `binary`."""
    workdir = tempfile.mkdtemp(prefix="xdf-build-")
    objects = []

    log("compiler: " + compiler())

    try:
        for source in DECODER_SOURCES + TEST_SOURCES:
            path = os.path.join(ROOT, source)
            if not os.path.isfile(path):
                error("missing source: " + path)
                return 2

            obj = os.path.join(workdir, os.path.basename(source) + ".o")
            flags = list(BASE_CFLAGS)
            flags += SANITIZERS + DEFINES
            flags += DECODER_CFLAGS
            flags += ["-I", os.path.join(ROOT, "inc"),
                      "-I", os.path.join(ROOT, "bddisasm", "include"),
                      "-I", os.path.join(ROOT, "tests", "x86_decode_fuzz")]

            if source in TEST_SOURCES:
                flags += TEST_CFLAGS

            command = [compiler()] + flags + ["-c", path, "-o", obj]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                error("compile failed: " + source)
                print(result.stderr)
                return 2

            if result.stderr.strip() and source in TEST_SOURCES:
                error("warnings in test source " + source + ":")
                print(result.stderr)

            objects.append(obj)

        command = [compiler()] + BASE_CFLAGS + SANITIZERS + objects + ["-o", binary]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            error("link failed")
            print(result.stderr)
            return 2

        log("built " + binary)
        return 0

    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)


def run_harness(binary: str, args: list) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Make sanitizer output deterministic and fully reported, and make a
    # sanitizer report fail the process (exitcode=1) rather than just log.
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=1")
    env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")

    return subprocess.run([binary] + args, capture_output=True, text=True, env=env)


def collect_cases(report_dir: str) -> list:
    if not os.path.isdir(report_dir):
        return []

    cases = []
    for name in sorted(os.listdir(report_dir)):
        if name.endswith("-repro.case"):
            cases.append(os.path.join(report_dir, name))

    return cases


def test_self(binary: str) -> int:
    log("running built-in regression fixtures")
    result = run_harness(binary, ["self-test"])

    print(result.stdout, end="")

    if result.returncode != 0:
        error("built-in fixtures failed")
        if result.stderr:
            print(result.stderr)
        return 1

    return 0


def test_fuzz(binary: str, cases: int, seed: int, report_dir: str) -> int:
    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir)

    os.makedirs(report_dir, exist_ok=True)

    log("fuzzing %d generated cases (seed %d)" % (cases, seed))
    result = run_harness(binary, ["run", "--seed", str(seed), "--cases", str(cases),
                                  "--report-dir", report_dir])

    print(result.stdout, end="")

    if result.stderr:
        print(result.stderr)

    recorded = collect_cases(report_dir)

    if result.returncode != 0 or recorded:
        error("fuzzing reported failures (%d sample(s))" % len(recorded))
        return 1

    return 0


def test_replay(binary: str, report_dir: str, expect_failures: bool = False) -> int:
    """Reload recorded samples.

    In normal use replay is a regression check: a sample is expected to no
    longer reproduce (exit code 0 from the harness). Pass expect_failures to
    assert instead that every sample *does* still reproduce, which is what you
    want when validating the test itself against a deliberately broken build.
    """
    cases = collect_cases(report_dir)

    if not cases:
        log("no failure samples to replay in " + report_dir)
        return 0

    problems = 0

    for case in cases:
        log("replaying " + os.path.basename(case))
        result = run_harness(binary, ["replay", "--case", case])

        print(result.stdout, end="")

        reproduced = result.returncode != 0

        if reproduced and not expect_failures:
            error("sample still reproduces: " + case)
            if result.stderr:
                print(result.stderr)
            problems += 1
        elif not reproduced and expect_failures:
            error("sample no longer reproduces: " + case)
            if result.stderr:
                print(result.stderr)
            problems += 1

    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="x86 decoder integration tests")
    parser.add_argument("--cases", type=int, default=20000,
                        help="number of generated cases (default 20000)")
    parser.add_argument("--seed", type=int, default=1,
                        help="generator seed (default 1)")
    parser.add_argument("--report-dir", default=os.path.join(HERE, "out", "report"),
                        help="where failure samples are written")
    parser.add_argument("--binary", default=os.path.join(HERE, "out", "bin", "x86_decode_fuzz"),
                        help="harness binary path")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse an existing harness binary")
    parser.add_argument("--replay", metavar="DIR",
                        help="only replay recorded failure samples in DIR")
    parser.add_argument("--expect-failures", action="store_true",
                        help="with --replay: require every sample to still reproduce "
                             "(used to validate the suite against a broken build)")
    parser.add_argument("--skip-self-test", action="store_true",
                        help="skip the built-in regression fixtures")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.binary)), exist_ok=True)

    if not args.no_build:
        rc = build(args.binary)
        if rc != 0:
            return rc
    elif not os.path.isfile(args.binary):
        error("binary not found: " + args.binary)
        return 2

    if args.replay:
        return test_replay(args.binary, args.replay, args.expect_failures)

    rc = 0

    if not args.skip_self_test:
        rc |= test_self(args.binary)

    rc |= test_fuzz(args.binary, args.cases, args.seed, args.report_dir)

    if rc == 0:
        log("all decoder invariants held")
    else:
        error("decoder invariant violations detected; samples in " + args.report_dir)

    return rc


if __name__ == "__main__":
    sys.exit(main())
