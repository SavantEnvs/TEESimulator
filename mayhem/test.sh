#!/usr/bin/env bash
#
# mayhem/test.sh — runs the known-answer suite mayhem/build.sh built (build/tests/kat): the tjson reader,
# the control channel's base64 and message handlers (driven over a socketpair), KeyMint name
# rendering and the redaction token, each against asserted values. The pass/fail counts come from the
# runner's own output, so a runner that exits 0 without running the checks fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
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

KAT="$SRC/build/tests/kat"
EXPECTED_MIN=60
if [ ! -x "$KAT" ]; then
  echo "test runner $KAT is missing; mayhem/build.sh should have built it" >&2
  emit_ctrf "tee-kat" 0 1 0
  exit 1
fi

out="$("$KAT" 2>&1)"
rc=$?
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | grep -c '^KAT PASS ')
failed=$(printf '%s\n' "$out" | grep -c '^KAT FAIL ')
summary=$(printf '%s\n' "$out" | grep '^KAT-SUMMARY ' | tail -n1)

if [ "$summary" != "KAT-SUMMARY passed=$passed failed=$failed" ] || [ "$passed" -lt "$EXPECTED_MIN" ]; then
  echo "runner output is inconsistent (summary='$summary', counted passed=$passed failed=$failed, expected at least $EXPECTED_MIN passes)" >&2
  failed=$(( failed + 1 ))
fi
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
emit_ctrf "tee-kat" "$passed" "$failed" 0
