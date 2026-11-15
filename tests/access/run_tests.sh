#!/bin/sh
# Build and run the access-graph integration tests against libbddisasm.
#
# Usage:
#   ./run_tests.sh                       # auto-detect the library in the tree
#   ./run_tests.sh path/to/libbddisasm.a # explicit library
#   BDDISASM_LIB=... ./run_tests.sh      # same, via environment
#   ./run_tests.sh -- <extra args>       # extra args go to the test binary
#
# Exits 0 when every sample passes (documented deviations excluded) and the opcode sweep reports
# no unexpected structural violation.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cc=${CC:-cc}

lib=${BDDISASM_LIB:-}
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

if [ -z "$lib" ]; then
    if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
        lib=$1
        shift
    fi
fi

if [ -z "$lib" ]; then
    for candidate in \
        "$root/bin/x64/Release/libbddisasm.a" \
        "$root/bin/x64/Debug/libbddisasm.a" \
        "$root/build/release/libbddisasm.a" \
        "$root/build/debug/libbddisasm.a" \
        "$root/build/debug-sanitizers/libbddisasm.a"
    do
        if [ -f "$candidate" ]; then
            lib=$candidate
            break
        fi
    done
fi

if [ -z "$lib" ] || [ ! -f "$lib" ]; then
    echo "error: libbddisasm.a not found; build it (make -C bddisasm) or pass its path" >&2
    exit 2
fi

out=$(mktemp -d "${TMPDIR:-/tmp}/bdd-access-XXXXXX")
trap 'rm -rf "$out"' EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

# bddisasm leaves nd_memset/nd_vsnprintf_s to the integrator; provide the CRT-backed ones the same
# way disasmtool does, so this builds against a plain static library.
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

"$cc" -std=c11 -O1 -Wall -Wextra -Wno-unused-parameter \
    -I"$root/inc" \
    "$here/access_graph.c" "$here/access_graph_test.c" "$out/crt_shim.c" "$lib" \
    -o "$out/access_graph_test"

exec "$out/access_graph_test" "$@"
