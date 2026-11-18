#!/bin/sh
# Build the LaminaDB binary and the fsync fault injector used by the harness.
#
# The checked-in bin/laminad is a macOS Mach-O build; it cannot run on Linux.
# Build from source instead of trusting the artifact.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
out=${1:-/tmp/lamina-durability}
mkdir -p "$out"
cd "$root"
go build -trimpath -o "$out/laminad" ./cmd/laminad

# Use a real C compiler. On some hosts "cc" in PATH is a wrapper shim rather
# than a compiler; prefer an explicit gcc/clang path when one exists.
cc_bin=""
for candidate in /usr/bin/gcc /usr/bin/clang gcc clang cc; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" --version 2>/dev/null | grep -qE 'gcc|clang|GCC|Clang'; then
            cc_bin=$candidate
            break
        fi
    fi
done
if [ -z "$cc_bin" ]; then
    echo "no working C compiler found" >&2
    exit 1
fi
"$cc_bin" -O2 -Wall -o "$out/fsync_inject" durability/faults/fsync_inject.c
echo "binary:   $out/laminad"
sha256sum "$out/laminad" 2>/dev/null || shasum -a 256 "$out/laminad"
echo "injector: $out/fsync_inject"
sha256sum "$out/fsync_inject" 2>/dev/null || shasum -a 256 "$out/fsync_inject"
