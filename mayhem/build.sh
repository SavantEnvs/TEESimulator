#!/usr/bin/env bash
#
# mayhem/build.sh — builds the fuzz harnesses, their standalone reproducers and the known-answer test
# runner for TEESimulator's host-compilable C++ (common/: tjson reader, control channel, KeyMint
# names, redaction). The Android/NDK build (Gradle, Rust TA, injector) needs the uninitialised
# third_party/ submodules and is not part of this layer.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/standalone" "$B/tests"

INC="-I$SRC/common -I$SRC/injector/include -I$SRC/rust/teesim-km/include -I$SRC/mayhem/shim -I$SRC/mayhem"
LANGFLAGS="-std=c++20 -fno-exceptions -fno-rtti -O1"
LIBSRC="common/json.cpp common/km_names.cpp common/redact.cpp common/log_context.cpp mayhem/tag_kind.cc mayhem/router_stub.cc"

# 1) The project's code, sanitized, twice: once with SanCov instrumentation for libFuzzer and once
#    without, for the run-once standalone reproducers (no libFuzzer runtime to provide the callbacks).
compile_all() {
  local dir="$1"; shift
  for f in $LIBSRC; do
    # json.cpp:236 casts any out-of-range double (1e30, 18446744073709551615) to int64_t, which is UB
    # but yields a fixed value on every target; left on, it ends every run on the first big number.
    relax=""; [ "$f" = common/json.cpp ] && relax="-fno-sanitize=float-cast-overflow"
    $CXX $LANGFLAGS $SANITIZER_FLAGS $relax $DEBUG_FLAGS "$@" $INC -c "$f" -o "$dir/$(basename "${f%.*}").o" &
    while [ "$(jobs -r | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
  done
  $CXX $LANGFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS "$@" -c mayhem/lsan_off.cc -o "$dir/lsan_off.o"
  wait
}
compile_all "$B/fuzz" -fsanitize=fuzzer-no-link
compile_all "$B/standalone"

# libFuzzer-free standalone main, as a C object so its LLVMFuzzerTestOneInput reference stays unmangled.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone/main.o"

# 2) Harnesses. common/control.cpp is compiled inside harness_control.cpp (its handlers are in an
#    anonymous namespace), so the control channel is instrumented like the library objects.
for t in json:fuzz_json_parse control:fuzz_control_config km_names:fuzz_km_names; do
  h="mayhem/harness_${t%%:*}.cpp"; name="${t##*:}"
  $CXX $LANGFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $INC -c "$h" -o "$B/fuzz/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$B"/fuzz/{json,km_names,redact,log_context,tag_kind,router_stub,lsan_off}.o \
      -lcrypto -o "$OUT/$name"
  $CXX $LANGFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS $INC -c "$h" -o "$B/standalone/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone/$name.o" "$B/standalone/main.o" "$B"/standalone/{json,km_names,redact,log_context,tag_kind,router_stub,lsan_off}.o \
      -lcrypto -o "$OUT/$name-standalone"
done

# 3) The known-answer test runner, with normal flags (no sanitizers).
$CXX -std=c++20 -fno-exceptions -fno-rtti -O2 $COVERAGE_FLAGS $INC mayhem/kat.cpp $LIBSRC -lcrypto -o "$B/tests/kat"
