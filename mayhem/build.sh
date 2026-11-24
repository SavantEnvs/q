#!/usr/bin/env bash
#
# mayhem/build.sh — build the q fuzz harnesses and the q test suite.
#
# q_lib is header-only (C++20); it needs only the `infra` submodule's headers. The harnesses
# include q's headers directly, so the fuzzed library code is compiled into each harness with
# $SANITIZER_FLAGS. The top-level CMake is not used: it would also build q_io, which fetches
# rtaudio/libremidi from the network and needs audio/MIDI device libraries.
#
# fuzz_wav_reader also compiles q_io/src/audio_file.cpp (vendored dr_wav), which needs no device library.
#
# Outputs (all under mayhem/build/, gitignored):
#   fuzz_<name>              libFuzzer binaries (the Mayhem targets)
#   fuzz_<name>-standalone   run-once reproducers (StandaloneFuzzTargetMain)
#   tests/test_<name>        upstream Catch test runners, NORMAL flags (run by mayhem/test.sh)
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

# cycfi/infra headers: the submodule when it is checked out, else the pinned copy the Dockerfile
# caches (same commit as the submodule pin at integration time).
INFRA_INCLUDE="$SRC/infra/include"
if [ ! -f "$INFRA_INCLUDE/infra/support.hpp" ]; then
   INFRA_INCLUDE="$(ls -d /opt/toolchains/deps/infra-*/src/include 2>/dev/null | head -n1)"
fi
if [ -z "$INFRA_INCLUDE" ] || [ ! -f "$INFRA_INCLUDE/infra/support.hpp" ]; then
   echo "build.sh: cycfi/infra headers not found (submodule infra/ or /opt/toolchains/deps/infra-*)" >&2
   exit 1
fi

OUT="$SRC/mayhem/build"
mkdir -p "$OUT/tests"

INCLUDES=(-I"$SRC/q_lib/include" -I"$INFRA_INCLUDE")
CXXSTD=(-std=c++20)

# 1+2) The harnesses: q's headers are compiled into each, so the library is instrumented too.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

HARNESSES=(note_number file_reader byte_reader packet_reader ci_responder ci_initiator dx_sysex ump_endpoint wav_reader)

build_harness() {
   local h="$1"
   local src="$SRC/mayhem/harnesses/fuzz_${h}.cpp"
   local extra=() objs=() sobjs=()
   # fuzz_wav_reader also compiles q_io's WAV reader (and its vendored dr_wav), the code it fuzzes.
   if [ "$h" = wav_reader ]; then
      extra=(-I"$SRC/q_io/include" -I"$SRC/q_io/external/include")
      $CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link "${INCLUDES[@]}" \
         "${extra[@]}" -c "$SRC/q_io/src/audio_file.cpp" -o "$OUT/audio_file.o"
      $CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INCLUDES[@]}" \
         "${extra[@]}" -c "$SRC/q_io/src/audio_file.cpp" -o "$OUT/audio_file-standalone.o"
      objs=("$OUT/audio_file.o")
      sobjs=("$OUT/audio_file-standalone.o")
   fi
   # The fuzzer object carries SanitizerCoverage (fuzzer-no-link); the standalone one does not.
   $CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link "${INCLUDES[@]}" \
      "${extra[@]}" -c "$src" -o "$OUT/fuzz_${h}.o"
   $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_${h}.o" "${objs[@]}" \
      "$OUT/lsan_off.o" -o "$OUT/fuzz_${h}"
   $CXX "${CXXSTD[@]}" $SANITIZER_FLAGS $DEBUG_FLAGS -O1 "${INCLUDES[@]}" \
      "${extra[@]}" -c "$src" -o "$OUT/fuzz_${h}-standalone.o"
   $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/fuzz_${h}-standalone.o" "${sobjs[@]}" \
      "$OUT/standalone_main.o" "$OUT/lsan_off.o" -o "$OUT/fuzz_${h}-standalone"
}

# 3) The upstream Catch tests that need only q_lib (no q_io, no audio files), with NORMAL flags.
TESTS=(
   midi/midi_processor midi/midi_parameters midi/midi_controllers midi/midi_byte_reader
   midi/midi_modes midi/midi_mpe midi/midi_mpe_spec midi/midi2_packet midi/midi2_messages
   midi/midi2_builders midi/midi2_scaling midi/midi2_translate midi/midi2_sysex midi/midi2_utility
   midi/midi2_flex midi/midi2_per_note midi/midi2_stream midi/midi_ci midi/midi_ci_initiator
   midi/midi_ci_profile_initiator midi/midi_ci_property_initiator midi/midi_ci_process
   midi/midi_ci_profiles midi/midi_ci_property midi/midi2_endpoint midi/midi2_inquiry
   midi/midi2_sysex_writer midi/midi2_sysex8_writer midi/midi_file_reader
   synth/fm/dx_sysex synth/fm/dx_patcher synth/fm/dx_patcher_voice synth/fm/fm_operator
   support/decibel utility/bitset utility/ring_buffer
)

build_test() {
   local t="$1"
   local name
   name="test_$(basename "$t")"
   $CXX "${CXXSTD[@]}" -O1 $COVERAGE_FLAGS "${INCLUDES[@]}" -I"$SRC/test" \
      "$SRC/test/${t}.cpp" -o "$OUT/tests/${name}"
}

export OUT

# Build in parallel; any failure fails the build.
pids=()
run_limited() {
   while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n; done
   "$@" &
   pids+=($!)
}
for h in "${HARNESSES[@]}"; do run_limited build_harness "$h"; done
for t in "${TESTS[@]}"; do run_limited build_test "$t"; done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" -eq 0 ] || { echo "build.sh: a harness or test failed to build" >&2; exit 1; }

printf '%s\n' "${TESTS[@]}" > "$OUT/tests/list.txt"
echo "build.sh: built ${#HARNESSES[@]} harnesses and ${#TESTS[@]} test runners into $OUT"
