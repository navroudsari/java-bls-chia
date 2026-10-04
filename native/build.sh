#!/bin/sh
#
# Builds the native library (blst + chia_bls.c shim) for the host platform.
#
# Usage: native/build.sh [output-resources-dir]
#
# The library is written to <output-resources-dir>/native/<os>-<arch>/, the
# path the Java loader looks up on the classpath. Override the compiler with CC.
#
# blst is compiled with __BLST_PORTABLE__ (as chia-bls does via blst's
# "portable" feature): CPU features such as ADX are detected at runtime, so the
# binary runs on any CPU of the target architecture, not just the build host.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/../target/native-resources"}
CC=${CC:-cc}

if [ ! -f "$HERE/blst/src/server.c" ]; then
    echo "blst sources missing; run: git submodule update --init" >&2
    exit 1
fi

case "$(uname -s)" in
    Linux)                os=linux;   lib=libchiabls.so ;;
    Darwin)               os=macos;   lib=libchiabls.dylib ;;
    MINGW*|MSYS*|CYGWIN*) os=windows; lib=chiabls.dll ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64|AMD64) arch=x86_64 ;;
    aarch64|arm64)      arch=aarch64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

dest="$OUT/native/$os-$arch"
mkdir -p "$dest"

CFLAGS="-O2 -fno-builtin -fPIC -Wall -Wextra -Werror -D__BLST_PORTABLE__ -I$HERE/blst/src"
if [ "$arch" = x86_64 ]; then
    CFLAGS="$CFLAGS -mno-avx"   # avoid costly AVX/SSE transitions, as blst does
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

(set -x; $CC $CFLAGS -c "$HERE/chia_bls.c" -o "$tmp/chia_bls.o")
(set -x; $CC $CFLAGS -c "$HERE/blst/build/assembly.S" -o "$tmp/assembly.o")

case "$os" in
    linux)
        (set -x; $CC -shared -o "$dest/$lib" "$tmp/chia_bls.o" "$tmp/assembly.o" \
            -Wl,-Bsymbolic -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now) ;;
    macos)
        (set -x; $CC -dynamiclib -o "$dest/$lib" "$tmp/chia_bls.o" "$tmp/assembly.o") ;;
    windows)
        (set -x; $CC -shared -o "$dest/$lib" "$tmp/chia_bls.o" "$tmp/assembly.o" \
            -Wl,--export-all-symbols -static-libgcc) ;;
esac

echo "built $dest/$lib"
