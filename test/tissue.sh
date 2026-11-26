#!/bin/sh
# The tissue: a fleet keeping cells alive with no scheduler. As root or not:
#   sudo sh test/tissue.sh /usr/local/bin/capsule
#   sh test/tissue.sh /usr/local/bin/capsule
# Three hosts are played on one machine, each with its own settings and
# data, sharing a ledger. Needs busybox-static, systemd, and reaches the
# drand beacon if it can.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d /tmp/capsule-tissue.XXXXXX)
chmod 755 "$W"
USERFLAG=--user
[ "$(id -u)" = 0 ] && USERFLAG=
export CAPSULE_HELPER=off
on() { h=$1; shift; env CAPSULE_CONFIG="$W/$h/conf" CAPSULE_DATA="$W/$h/data" CAPSULE_RUN="$W/$h/run" "$CAPSULE" "$@"; }
oper() { env CAPSULE_CONFIG="$W/oper/conf" CAPSULE_DATA="$W/oper/data" "$CAPSULE" "$@"; }
cleanup() {
  set +e
  systemctl $USERFLAG stop 'capsule-cell-*-????????.service' 2>/dev/null
  for h in a b c; do for id in $(on $h ps 2>/dev/null | tail -n +2 | cut -d' ' -f1); do on $h kill "$id"; done; done
  sleep 1
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
fail() {
  echo "FAIL: $1"; oper tissue status 2>&1 | sed 's/^/  /'
  for h in a b c; do echo "  host $h runs: $(on $h ps 2>/dev/null | tail -n +2 | cut -d' ' -f1 | tr '\n' ' ')"; done
  tail -n 15 tend.log 2>/dev/null | sed 's/^/  tend: /'
  exit 1
}
pass() { echo "ok   $1"; }

for k in dev op rogue; do "$CAPSULE" keygen $k >/dev/null; done
mkdir -p ledger oper/conf
echo "file://$W/ledger" > oper/conf/ledger
for h in a b c; do
  mkdir -p $h/conf/trust.d $h/conf/operators.d
  cp dev.pub $h/conf/trust.d/; cp op.pub $h/conf/operators.d/
  echo "file://$W/ledger" > $h/conf/ledger
  on $h host -export > $h.host
done

release() { # $1 = name, $2 = command as JSON, $3 = extra manifest fields, $4 = a marker to tell releases apart
  rm -rf "src/$1"; mkdir -p "src/$1/rootfs/bin"
  cp "$BUSYBOX" "src/$1/rootfs/bin/busybox"; ln -s busybox "src/$1/rootfs/bin/sleep"
  echo "${4:-1}" > "src/$1/rootfs/release"
  printf '{"name":"%s","command":%s%s,"limits":{"memory":"32M","pids":32}}\n' "$1" "$2" "${3:-}" > "src/$1/capsule.json"
  "$CAPSULE" seal -key dev.key "src/$1" >/dev/null
  oper publish -key dev.key -trust dev.pub "src/$1" >/dev/null
}
SLEEP='["/bin/sleep","3600"]'
release web "$SLEEP" ',"network":"mesh","mesh":{"peers":[{"name":"db","out":[5432]}]}'
release db "$SLEEP" ',"network":"mesh","mesh":{"peers":[{"name":"web","in":[5432]}]}'
release spare "$SLEEP"
release cache "$SLEEP"

count() { n=0; for h in a b c; do n=$((n + $(on $h ps 2>/dev/null | grep -c "^$1-" || true))); done; echo $n; }
where() { for h in a b c; do on $h ps 2>/dev/null | grep -q "^$1-" && printf '%s ' $h; done; }
tend() { for h in "$@"; do on $h tend 2>>tend.log & done; wait; } # each host on its own, as their timers would
# settle <hosts> until <condition>: let the hosts make their passes until it holds
until_true() { hosts=$1; shift; for i in $(seq 1 30); do tend $hosts; if "$@"; then return 0; fi; sleep 1; done; return 1; }

cat > tissue.json <<JSON
{"name":"prod","lease":4,
 "cells":{"web":{"root":true,"min":2,"standby":"warm"},"spare":{}},
 "hosts":[{"file":"a.host"},{"file":"b.host"},{"file":"c.host"}]}
JSON
out=$(oper tissue -key op.key tissue.json 2>&1)
echo "$out" | grep -q 'db x1, web x2' && pass "the tissue names one root; what it needs is worked out from the manifests" || fail "publish: $out"

settled() { [ "$(count web)" = 2 ] && [ "$(count db)" = 1 ]; }
until_true "a b c" settled || fail "did not converge: web $(count web), db $(count db): $(cat tend.log)"
[ "$(where web | wc -w)" = 2 ] && pass "two instances of web came up, on two different hosts" || fail "web is on: $(where web)"
[ "$(count db)" = 1 ] && pass "db was grown because web needs it, though the tissue does not list it" || fail "db count $(count db)"
[ "$(count spare)" = 0 ] && pass "a listed cell that is no root and that nothing needs is not run" || fail "spare is running"
tend a b c; tend a b c
settled && pass "further passes change nothing" || fail "not stable: web $(count web), db $(count db)"
status=$(oper tissue status)
[ "$(echo "$status" | grep -c ' alive ')" = 6 ] && pass "status shows three hosts and three slots alive" || fail "status: $status"
echo "$status" | grep -E '^(web|db) ' | grep -q '?' && echo "note: the beacon was out of reach, so draws were unproven" || pass "every placement names the beacon round that decided it"
spareHost=""; for h in a b c; do on $h ps | grep -q '^web-' || spareHost=$h; done
[ -d "$spareHost/data/apps/web" ] && pass "the understudy keeps web fetched and checked, without running it" || fail "no warm copy on $spareHost"
busy=$(where web | cut -d' ' -f1)
on $busy log >/dev/null 2>&1 && on $busy log | grep -q tissue && pass "what a host did for the tissue is in its signed record" || fail "nothing in the record"

# ---- a host goes silent ----
dbHost=$(where db | tr -d ' ')
others=$(echo "a b c" | sed "s/$dbHost//")
elsewhere() { for h in $others; do on $h ps | grep -q '^db-' && return 0; done; return 1; }
start=$(date +%s)
until_true "$others" elsewhere || fail "nobody took db over from $dbHost: $(cat tend.log)"
took=$(( $(date +%s) - start ))
pass "when a host stops renewing, another takes its slot (after ${took}s, with a 12s lease)"
oper tissue status | grep '^db ' | awk '{exit !($4 == 2)}' && pass "the takeover is a new term of the lease" || fail "term: $(oper tissue status | grep '^db ')"
on $dbHost ps | grep -q '^db-' || fail "test: the silent host should still be running its copy"
gone() { ! on $dbHost ps | grep -q '^db-'; }
until_true "$dbHost" gone && pass "the old holder, back in touch, sees the higher term and stops its copy" || fail "the old holder kept running db"
until_true "a b c" settled || fail "did not settle after the host came back: web $(count web), db $(count db)"
pass "the tissue is whole again: two web, one db"

# ---- generations ----
release web "$SLEEP" ',"network":"mesh","mesh":{"peers":[{"name":"db","out":[5432]}]}' 2
low=2
for i in $(seq 1 20); do
  for h in a b c; do on $h tend 2>>tend.log || true; n=$(count web); [ "$n" -lt "$low" ] && low=$n; done
  tend a b c
  [ "$(oper tissue status | grep '^web ' | grep -c ' current ')" = 2 ] && break
  sleep 1
done
[ "$(oper tissue status | grep '^web ' | grep -c ' current ')" = 2 ] && pass "a new release reached both instances" || fail "generation did not complete"
[ "$low" -ge 1 ] && pass "they were replaced one at a time: web was never down everywhere" || fail "web went down to $low instances during the rollout"

release web '["/bin/missing"]' ',"network":"mesh","mesh":{"peers":[{"name":"db","out":[5432]}]}' 3
held() { oper tissue status | grep '^web ' | grep -q 'held back'; }
until_true "a b c" held || fail "a release that cannot start was not held back: $(tail -5 tend.log)"
until_true "a b c" settled || fail "web did not recover after the bad release: $(count web)"
[ "$(oper tissue status | grep '^web ' | grep -c 'held back')" = 2 ] && pass "a release that does not come up is tried on one instance, put back, and held back everywhere" || fail "held back: $(oper tissue status | grep '^web ')"

release web "$SLEEP" ',"network":"mesh","mesh":{"peers":[{"name":"db","out":[5432]}]}' 4
current() { [ "$(oper tissue status | grep '^web ' | grep -c ' current ')" = 2 ]; }
until_true "a b c" current && pass "the next good release goes out as usual" || fail "stuck after a held-back release"

# ---- who may say what the tissue is ----
cp ledger/tissue/current good.tissue
"$CAPSULE" tissue -key rogue.key -o rogue.signed tissue.json >/dev/null
python3 -c "import json,sys; print(json.dumps(json.load(open('rogue.signed'))))" > ledger/tissue/current
out=$(on a tend 2>&1 || true)
echo "$out" | grep -q 'not one this host follows' && settled && pass "a tissue signed by someone who is not an operator is not followed" || fail "rogue tissue: $out"
oper tissue -key op.key tissue.json >/dev/null
tend a b c
cp good.tissue ledger/tissue/current
out=$(on a tend 2>&1 || true)
echo "$out" | grep -q 'older tissue' && pass "an older tissue put back in the ledger is refused" || fail "replayed tissue: $out"

# ---- a hot standby, a strict cell, and a host leaving ----
cat > tissue.json <<JSON
{"name":"prod","lease":4,
 "cells":{"web":{"root":true,"min":2},"cache":{"root":true,"standby":"hot"},"db":{"takeover":"strict"}},
 "hosts":[{"file":"a.host"},{"file":"b.host"},{"file":"c.host"}]}
JSON
oper tissue -key op.key tissue.json >/dev/null
hot() { [ "$(count cache)" = 2 ] && settled; }
until_true "a b c" hot || fail "hot standby: cache runs $(count cache) times"
[ "$(oper tissue status | grep -c '^cache ')" = 1 ] && pass "a hot standby runs beside the holder: two copies, one lease" || fail "cache slots: $(oper tissue status | grep '^cache ')"

dbHost=$(where db | tr -d ' ')
cp $dbHost/conf/ledger ledger.keep
echo "vault+http://127.0.0.1:1/secret/none" > $dbHost/conf/ledger
export VAULT_TOKEN=unused # so the ledger is well-formed and simply cannot be reached
stopped() { ! on $dbHost ps | grep -q '^db-'; }
webBefore=$(on $dbHost ps | grep -c '^web-' || true)
until_true "$dbHost" stopped || fail "a strict cell kept running after its lease could not be renewed"
[ "$(on $dbHost ps | grep -c '^web-' || true)" = "$webBefore" ] && pass "cut off from the ledger, a host stops its strict cell as the lease runs out, and keeps the others" || fail "the host also stopped cells that are not strict"
cp ledger.keep $dbHost/conf/ledger
until_true "a b c" hot || fail "did not settle after the ledger came back"

cat > tissue.json <<JSON
{"name":"prod","lease":4,
 "cells":{"web":{"root":true,"min":2},"cache":{"root":true,"standby":"hot"},"db":{"takeover":"strict"}},
 "hosts":[{"file":"a.host"},{"file":"b.host"}]}
JSON
oper tissue -key op.key tissue.json >/dev/null
left() { [ -z "$(on c ps | tail -n +2)" ] && settled; }
until_true "a b c" left && pass "a host taken out of the tissue stops its cells, and the rest make up for it" || fail "host c still runs: $(on c ps)"
for h in a b c; do on $h log >/dev/null 2>&1 || fail "the record of host $h does not verify"; done
pass "every host's record is intact"
echo "all tissue checks passed"
