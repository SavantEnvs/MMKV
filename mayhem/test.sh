#!/usr/bin/env bash
#
# mayhem/test.sh — run MMKV's own POSIX unit tests (POSIX/demo, built by mayhem/build.sh with normal
# flags, asserts enabled). Each test asserts stored/loaded values internally (assert()/require()) and
# prints a "...: passed" line only after all of its checks succeed; a test passes here only when it
# exits 0 AND printed its expected final success line, so a no-op binary fails.
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

T="$SRC/build/test"
for t in UnitTest TestSingleKeyIV TestFileCopy TestThreadLock; do
  [ -x "$T/$t" ] || { echo "test.sh: missing $T/$t (build.sh should have built it)" >&2; emit_ctrf mmkv-posix-unittests 0 1; exit 1; }
done

scratch="$(mktemp -d "${TMPDIR:-/tmp}/mmkv-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
passed=0 failed=0

# run_test <name> <expected final line> <cmd...>
run_test() {
  local name="$1" expect="$2"; shift 2
  local out
  out="$(cd "$scratch" && TMPDIR="$scratch" "$@" 2>&1)"
  local rc=$?
  if [ $rc -eq 0 ] && grep -qxF -- "$expect" <<<"$out"; then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name (exit $rc)"; tail -n 20 <<<"$out"; failed=$((failed + 1))
  fi
}

mkdir -p "$scratch/unit"
run_test UnitTest "test first write after reopen overloads: passed" "$T/UnitTest" "$scratch/unit"
run_test TestSingleKeyIV "test single-key IV: safe replacements, compaction IVs, reload/reopen, sizes and plain control passed" "$T/TestSingleKeyIV" "$scratch"
run_test TestFileCopy "test file copy transfers: passed" "$T/TestFileCopy"
run_test TestThreadLock "test ThreadLock destruction: passed" "$T/TestThreadLock"

emit_ctrf mmkv-posix-unittests "$passed" "$failed"
