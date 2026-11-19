#!/usr/bin/env bash
#
# mayhem/build.sh — build MMKV's Core library (sanitized + SanCov) and the fuzz harnesses, plus
# upstream's own POSIX unit tests (normal flags) for mayhem/test.sh.
#
# Upstream builds Core with CMake (Core/CMakeLists.txt). That CMake file copies headers into the
# SOURCE tree (Core/include/MMKV, not gitignored), so this script compiles the same source list
# directly into gitignored build/ directories instead: Core/*.cpp, aes/*.cpp, aes/openssl/*.cpp,
# crc32/*.cpp, crc32/zlib/*.cpp (the platform files are #ifdef-guarded; on x86_64 the CMake file
# adds no assembly). MMKV_EMBED_ZLIB=1 is what CMake sets when no system libz is found: it uses
# the bundled crc32, so there is no external dependency. Re-runnable and offline.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
CORE="$SRC/Core"
DEFS="-DMMKV_EMBED_ZLIB=1"
mapfile -t CORE_SRCS < <(cd "$CORE" && ls *.cpp aes/*.cpp aes/openssl/*.cpp crc32/*.cpp crc32/zlib/*.cpp)
ARCH="$(uname -m)"
if [ "$ARCH" != "x86_64" ]; then
  echo "build.sh: only x86_64 is supported (CMake adds openssl_aesv8-armx.S elsewhere)" >&2
  exit 1
fi

# build_core <outdir> <flags...> : compile every Core source into <outdir>/libcore.a
build_core() {
  local out="$1"; shift
  local flags="$*"
  mkdir -p "$out/obj"
  rm -f "$out/libcore.a" "$out"/obj/*.o
  printf '%s\n' "${CORE_SRCS[@]}" | \
    xargs -P "$MAYHEM_JOBS" -I{} sh -c '
      o="$1/obj/$(echo "$2" | tr / _).o"
      exec $CXX -std=c++20 '"$flags"' '"$DEFS"' -I"$3" -c "$3/$2" -o "$o"' _ "$out" {} "$CORE"
  ar rcs "$out/libcore.a" "$out"/obj/*.o
}

# UBSan's `alignment` check is relaxed (only that one; ASan and the rest of UBSan stay halting):
# Core deliberately does word-sized unaligned loads (aes/openssl/openssl_cfb128.cpp's size_t XOR loop,
# MMBuffer.cpp reading the 8-byte length of mmap'd records at arbitrary offsets), which is benign on
# x86_64 and fired on the very first seed of every on-disk target, masking every other finding.
RELAX=""
case "$SANITIZER_FLAGS" in *undefined*|*alignment*) RELAX="-fno-sanitize=alignment" ;; esac
SANITIZER_FLAGS="$SANITIZER_FLAGS $RELAX"

# 1) Sanitized + coverage-instrumented Core for the fuzzers.
FUZZ_CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS"
case "$LIB_FUZZING_ENGINE" in *fuzzer*) FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link" ;; esac
FUZZ_OUT="$SRC/build/fuzz"
build_core "$FUZZ_OUT" "$FUZZ_CFLAGS"

# 2) Harnesses: libFuzzer binary + run-once standalone reproducer each.
mkdir -p "$FUZZ_OUT/h"
$CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ_OUT/h/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_OUT/h/standalone_main.o"
link_harness() {
  local name="$1" src="$2"; shift 2
  local hflags="-std=c++20 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS -I$CORE -I$SRC/mayhem/harnesses $*"
  $CXX $hflags $LIB_FUZZING_ENGINE "$SRC/mayhem/harnesses/$src" "$FUZZ_OUT/h/lsan_off.o" \
    "$FUZZ_OUT/libcore.a" -lpthread -o "$SRC/$name"
  $CXX $hflags "$SRC/mayhem/harnesses/$src" "$FUZZ_OUT/h/standalone_main.o" "$FUZZ_OUT/h/lsan_off.o" \
    "$FUZZ_OUT/libcore.a" -lpthread -o "$SRC/$name-standalone"
}
link_harness fuzz_mmkv_load        fuzz_mmkv_load.cpp
link_harness fuzz_mmkv_load_crypt  fuzz_mmkv_load.cpp -DFZ_CRYPT=1
link_harness fuzz_mmkv_load_expire fuzz_mmkv_load.cpp -DFZ_EXPIRE=1
link_harness fuzz_mmkv_restore     fuzz_mmkv_restore.cpp
link_harness fuzz_mmkv_value       fuzz_mmkv_value.cpp
link_harness fuzz_mmkv_ops         fuzz_mmkv_ops.cpp

# 3) Upstream's POSIX unit tests (POSIX/demo) with normal flags; asserts stay enabled (no NDEBUG).
TEST_OUT="$SRC/build/test"
TEST_CFLAGS="-O1 -g $COVERAGE_FLAGS"
# The tests include <MMKV/MMKV.h>; upstream's CMake copies Core headers to Core/include/MMKV. Point an
# include dir at Core itself instead (a symlink under the gitignored build/), so edits to Core apply.
mkdir -p "$TEST_OUT/include"
ln -sfn "$CORE" "$TEST_OUT/include/MMKV"
build_core "$TEST_OUT" "$TEST_CFLAGS"
for t in UnitTest TestSingleKeyIV TestFileCopy TestThreadLock; do
  $CXX -std=c++20 $TEST_CFLAGS $DEFS -I"$CORE" -I"$TEST_OUT/include" "$SRC/POSIX/demo/$t.cpp" "$TEST_OUT/libcore.a" \
    -lpthread -ldl $COVERAGE_FLAGS -o "$TEST_OUT/$t"
done
echo "build.sh: done"
