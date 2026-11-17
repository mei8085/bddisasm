#!/bin/sh
#
# Copyright (c) 2025 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
# Build and run the decode-to-text boundary tests.
#
# Usage:
#   ./tests/text_boundary/run_tests.sh                       # auto-detect libbddisasm.a
#   ./tests/text_boundary/run_tests.sh path/to/libbddisasm.a # explicit library
#   BDDISASM_LIB=... ./tests/text_boundary/run_tests.sh      # same, via environment
#
# Environment:
#   CC        C compiler (default: cc)
#   CFLAGS    extra compiler flags. Pass "-fsanitize=address,undefined" here (and build the library
#             with the same flags) to run the boundary checks under a sanitizer.
#
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cc=${CC:-cc}
cflags=${CFLAGS:-}

lib=${BDDISASM_LIB:-}

if [ -z "$lib" ] && [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    lib=$1
    shift
fi

if [ -z "$lib" ]; then
    for candidate in \
        "$root/bin/x64/Release/libbddisasm.a" \
        "$root/bin/x64/Debug/libbddisasm.a" \
        "$root/bin/x86/Release/libbddisasm.a" \
        "$root/bin/x86/Debug/libbddisasm.a" \
        "$root/build/release/libbddisasm.a" \
        "$root/build/debug/libbddisasm.a" \
        "$root/build/debug-sanitizers/libbddisasm.a" \
        "$root/build/libbddisasm.a"
    do
        if [ -f "$candidate" ]; then
            lib=$candidate
            break
        fi
    done
fi

if [ -z "$lib" ]; then
    lib=$(find "$root" -name 'libbddisasm.a' -type f 2>/dev/null | head -n 1)
fi

if [ -z "$lib" ] || [ ! -f "$lib" ]; then
    echo "error: libbddisasm.a not found; build it (make -C bddisasm) or pass its path" >&2
    echo "usage: $0 [path/to/libbddisasm.a]" >&2
    exit 2
fi

out=$(mktemp -d "${TMPDIR:-/tmp}/bdd-text-boundary-XXXXXX")
trap 'rm -rf "$out"' EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

# bddisasm leaves nd_memset/nd_vsnprintf_s to the integrator. Provide the CRT-backed ones the same way
# disasmtool does, so the test builds against a plain static library.
cat > "$out/crt_shim.c" <<'CRT'
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void *nd_memset(void *s, int c, size_t n) { return memset(s, c, n); }
int nd_vsnprintf_s(char *b, size_t size, size_t count, const char *fmt, va_list ap)
{
    (void)count;
    return vsnprintf(b, size, fmt, ap);
}
CRT

echo "library: $lib"

# shellcheck disable=SC2086
"$cc" -std=c11 -O1 -g -Wall -Wextra -Wno-unused-function $cflags \
    -I"$root/inc" \
    "$here/text_boundary_test.c" "$out/crt_shim.c" "$lib" \
    -o "$out/text_boundary_test"

exec "$out/text_boundary_test" "$@"
