#!/bin/sh
# Builds and runs every example, as root or as an ordinary user:
#   sh test/examples.sh
# Needs capsule installed, curl, and internet access for the first run
# (about 230 MB of downloads, kept in examples/.cache).
set -eu
REPO=$(dirname "$(dirname "$(realpath "$0")")")
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data"
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  pkill -TERM -P $$ 2>/dev/null || true
  sleep 2
  for id in $(capsule ps 2>/dev/null | grep -E '^(pyweb|pyjob|javaweb)-' | cut -d' ' -f1); do capsule kill "$id" 2>/dev/null || true; done
  sleep 1
  chmod -R u+rwx "$W" 2>/dev/null; rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }
get() { curl -fsS --max-time 5 "http://127.0.0.1:$1/" 2>/dev/null || true; }
wait_for() { for _ in $(seq 1 "$2"); do [ -n "$(get "$1")" ] && return 0; sleep 1; done; return 1; }

cd "$W"
capsule keygen dev
OUT="$REPO/examples/out"

sh "$REPO/examples/build.sh" python-web dev.key >/dev/null || fail "python-web did not build"
capsule run -trust dev.pub -publish 127.0.0.1:18000:8000 "$OUT/pyweb" > pyweb.out 2>&1 & WEB=$!
wait_for 18000 20 || fail "python-web did not answer: $(cat pyweb.out)"
get 18000 | grep -q "Hello from Python 3.12" || fail "unexpected answer from python-web: $(get 18000)"
kill -TERM $WEB; wait $WEB || true
capsule run -trust dev.pub -publish 127.0.0.1:18000:8000 "$OUT/pyweb" > pyweb.out 2>&1 & WEB=$!
wait_for 18000 20 || fail "python-web did not come back"
get 18000 | grep -q "Visit [3-9]" || fail "python-web forgot its visits across a restart: $(get 18000)"
kill -TERM $WEB; wait $WEB || true
pass "python-web: serves requests and keeps its count across a restart"

sh "$REPO/examples/build.sh" python-job dev.key >/dev/null || fail "python-job did not build"
capsule run -trust dev.pub -receipt receipt.json "$OUT/pyjob" | grep -q "^run 1 at " || fail "python-job did not report its first run"
capsule run -trust dev.pub "$OUT/pyjob" | grep -q "^run 2 at " || fail "python-job did not see its earlier report"
capsule receipt -host "$(capsule host | awk '/^sign/{print $2}')" receipt.json | grep -q "^status   0" || fail "the job's receipt does not verify"
pass "python-job: runs to the end, keeps its reports, and its receipt verifies"

sh "$REPO/examples/build.sh" java-web dev.key >/dev/null || fail "java-web did not build"
capsule run -trust dev.pub -publish 127.0.0.1:18080:8080 "$OUT/javaweb" > javaweb.out 2>&1 & JAVA=$!
wait_for 18080 90 || fail "java-web did not answer: $(tail -5 javaweb.out)"
sleep 10 # let the second replica finish starting
get 18080 | grep -q "Hello from Java 21" || fail "unexpected answer from java-web: $(get 18080)"
[ "$(capsule ps | grep -c '^javaweb-')" = 2 ] || fail "java-web is not running two replicas"
[ "$(for i in 1 2 3 4 5 6; do get 18080; done | sort -u | wc -l)" = 2 ] || fail "requests did not reach both java-web replicas"
kill -TERM $JAVA; wait $JAVA || true
pass "java-web: two replicas share one port and both answer"

echo "all checks passed"
