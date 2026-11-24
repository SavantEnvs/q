#!/usr/bin/env bash
#
# mayhem/test.sh — RUN q's own Catch test runners (built by mayhem/build.sh with normal flags).
#
# Each runner is one test file of upstream's test/ tree (midi, MIDI-CI, UMP, SMF, DX7 sysex, ...).
# Catch asserts known values; a runner passes only when it exits 0 AND reports
# "All tests passed", so a neutered (exit(0)) binary counts as a failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TESTDIR="$SRC/mayhem/build/tests"
LIST="$TESTDIR/list.txt"
if [ ! -f "$LIST" ]; then
  echo "test.sh: $LIST missing — run mayhem/build.sh first" >&2
  emit_ctrf "catch2" 0 1 0
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/q-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

passed=0 failed=0
while IFS= read -r t; do
  [ -n "$t" ] || continue
  name="test_$(basename "$t")"
  bin="$TESTDIR/$name"
  if [ ! -x "$bin" ]; then
    echo "FAIL $name (runner missing)"; failed=$((failed+1)); continue
  fi
  out="$(cd "$work" && "$bin" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && grep -q '^All tests passed' <<<"$out"; then
    echo "PASS $name: $(grep '^All tests passed' <<<"$out")"
    passed=$((passed+1))
  else
    echo "FAIL $name (exit $rc)"; tail -n 20 <<<"$out"
    failed=$((failed+1))
  fi
done < "$LIST"

emit_ctrf "catch2" "$passed" "$failed" 0
