#!/bin/sh
# What a tissue does for cells that must not be missed, or that keep data.
# As root (the part about a crash needs a sized volume) or not:
#   sudo sh test/takeover.sh /usr/local/bin/capsule
#   sh test/takeover.sh /usr/local/bin/capsule
# Three hosts are played on one machine. Needs busybox-static and systemd.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d /tmp/capsule-takeover.XXXXXX)
chmod 755 "$W"
ROOT=no; USERFLAG=--user
[ "$(id -u)" = 0 ] && { ROOT=yes; USERFLAG=; }
export CAPSULE_HELPER=off CAPSULE_PSK_TICKS=1200
on() { h=$1; shift; env CAPSULE_CONFIG="$W/$h/conf" CAPSULE_DATA="$W/$h/data" CAPSULE_RUN="$W/$h/run" "$CAPSULE" "$@"; }
oper() { env CAPSULE_CONFIG="$W/oper/conf" CAPSULE_DATA="$W/oper/data" "$CAPSULE" "$@"; }
cleanup() {
  set +e
  pkill -CONT -f "run -tissue $W/" 2>/dev/null
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
  tail -n 12 tend.log 2>/dev/null | cut -c1-220 | sed 's/^/  tend: /'
  exit 1
}
pass() { echo "ok   $1"; }

for k in dev op; do "$CAPSULE" keygen $k >/dev/null; done
mkdir -p ledger oper/conf cards
echo "file://$W/ledger" > oper/conf/ledger
for h in a b c; do
  mkdir -p $h/conf/trust.d $h/conf/operators.d
  cp dev.pub $h/conf/trust.d/; cp op.pub $h/conf/operators.d/
  echo "file://$W/ledger" > $h/conf/ledger
  ln -s "$W/cards" $h/conf/peers.d       # one folder of cards for the whole fleet
  echo 127.0.0.1 > $h/conf/advertise     # where this host's tunnels can be reached
  on $h host -export > $h.host
  "$CAPSULE" delegate -key dev.key -host "$(on $h host | sed -n 's/^sign *//p')" feed > $h/conf/delegation
done
release() { # $1 = name, $2 = shell script, $3 = extra manifest fields
  rm -rf "src/$1"; mkdir -p "src/$1/rootfs/bin"
  cp "$BUSYBOX" "src/$1/rootfs/bin/busybox"; for a in sh sleep cat echo; do ln -s busybox "src/$1/rootfs/bin/$a"; done
  printf '{"name":"%s","command":["/bin/sh","-c","%s"]%s,"limits":{"memory":"32M","pids":32}}\n' "$1" "$2" "${3:-}" > "src/$1/capsule.json"
  "$CAPSULE" seal -key dev.key "src/$1" >/dev/null
  oper publish -key dev.key -trust dev.pub "src/$1" >/dev/null
}
count() { n=0; for h in a b c; do n=$((n + $(on $h ps 2>/dev/null | grep -c "^$1-" || true))); done; echo $n; }
where() { for h in a b c; do on $h ps 2>/dev/null | grep -q "^$1-" && printf '%s ' $h; done; true; }
tend() { for h in "$@"; do on $h tend 2>>tend.log & done; wait; }
until_true() { hosts=$1; shift; for i in $(seq 1 40); do tend $hosts; if "$@"; then return 0; fi; sleep 1; done; return 1; }
holder() { oper tissue status | awk -v c="$1" '$1 == c {print $3}' | head -1; } # first 8 hex of the host id
name_of() { for h in a b c; do [ "$(on $h host | sed -n 's/^id *//p' | base64 -d | od -An -tx1 | tr -d ' \n' | cut -c1-8)" = "$1" ] && echo $h; done; true; }
publish() { oper tissue -key op.key tissue.json >/dev/null; }

# ---- a hot standby that takes over in milliseconds ----
release feed 'sleep 3600' ',"network":"mesh","mesh":{"peers":[]}'
cat > tissue.json <<JSON
{"name":"fast","lease":6,"cells":{"feed":{"root":true,"standby":"hot","detect":"100ms"}},
 "hosts":[{"file":"a.host"},{"file":"b.host"}]}
JSON
publish
both() { [ "$(count feed)" = 2 ]; }
until_true "a b" both || fail "the holder and its hot standby did not both come up: $(count feed)"
H=$(name_of "$(holder feed)"); S=$(echo "a b" | sed "s/$H//" | tr -d ' ')
role() { cat "$W/$1/data/tissue/state/feed/role" 2>/dev/null; }
tend a b
[ "$(role $H)" = holder ] && [ "$(role $S)" = standby ] && pass "each instance is told its role: holder on one host, standby on the other" || fail "roles: $H=$(role $H) $S=$(role $S)"
id=$(on $S ps | grep '^feed-' | cut -d' ' -f1)
pid=$(head -1 "$(readlink "$W/$S/run/$id.cg")/cgroup.procs")
[ "$(cat /proc/$pid/root/run/capsule/role 2>/dev/null)" = standby ] && pass "the program can read its role at /run/capsule/role" || fail "role inside the capsule: $(cat /proc/$pid/root/run/capsule/role 2>&1)"
hears() { [ "$(cat "$W/$S/data/tissue/state/feed/heard" 2>/dev/null)" = 1 ]; }
for i in $(seq 1 60); do hears && break; sleep 0.5; done
hears || fail "the standby never heard the holder"
sleep 1
[ "$(role $S)" = standby ] || fail "the standby promoted itself while the holder was alive: $(role $S)"
pass "while the holder's heartbeat arrives, the standby stays a standby"
sup="run -tissue $W/$H/data/tissue/state/feed"
start=$(date +%s%N)
pkill -STOP -f "$sup"            # the holder's supervisor freezes: its heartbeat stops
for i in $(seq 1 400); do [ "$(role $S)" = "holder promoted" ] && break; sleep 0.005; done
took=$(( ($(date +%s%N) - start) / 1000000 ))
pkill -CONT -f "$sup"
[ "$(role $S)" = "holder promoted" ] || fail "the standby did not take over within 2s: $(role $S); $(on $S log | tail -2)"
[ "$took" -lt 600 ] && pass "the standby took over ${took}ms after the holder fell silent (set to 100ms; no ledger, no timer involved)" || fail "takeover took ${took}ms"
on $S log | grep -q 'standby took over after' && pass "the takeover is in the standby host's signed record" || fail "no record of the takeover"
demoted() { [ "$(role $S)" = standby ]; }
until_true "a b" demoted && pass "the holder came back within its lease, so once it has renewed, the tissue makes the standby a standby again" || fail "after the holder returned: $(role $S)"

# ---- a strict cell is stopped by its own supervisor ----
release once 'sleep 3600'
cat > tissue.json <<JSON
{"name":"fast","lease":4,"cells":{"once":{"root":true,"takeover":"strict"}},
 "hosts":[{"file":"a.host"},{"file":"b.host"},{"file":"c.host"}]}
JSON
publish
one() { [ "$(count once)" = 1 ] && [ "$(count feed)" = 0 ]; }
until_true "a b c" one || fail "the strict cell did not come up alone: once $(count once), feed $(count feed)"
H=$(where once | tr -d ' ')
[ -s "$W/$H/data/tissue/state/once/until" ] || fail "the supervisor was not told how long the lease is good"
start=$(date +%s)
for i in $(seq 1 40); do on $H ps | grep -q '^once-' || break; sleep 1; done   # nobody tends: no timer, no pass, nothing
on $H ps | grep -q '^once-' && fail "a strict cell kept running with its lease not renewed and nothing tending it"
pass "with no pass running at all, a strict cell's own supervisor stops it when the lease runs out ($(( $(date +%s) - start ))s; lease 12s)"

# ---- data that follows its cell ----
STORE='[ -f /data/id ] || cat /proc/sys/kernel/random/uuid > /data/id; sleep 3600'
release store "$STORE" ',"volumes":[{"name":"data","path":"/data"}]'
tissue_store() { cat > tissue.json <<JSON
{"name":"fast","lease":4,"cells":{"store":{"root":true,"standby":"warm","snapshot":"30s"}},
 "hosts":[$1]}
JSON
publish; }
tissue_store '{"file":"a.host"},{"file":"b.host"},{"file":"c.host"}'
up() { [ "$(count store)" = 1 ]; }
until_true "a b c" up || fail "store did not come up"
H=$(where store | tr -d ' ')
idfile() { echo "$W/$1/data/volumes/store/data/id"; }
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$(idfile $H)" ] && break; sleep 0.5; done
ID=$(cat "$(idfile $H)")
[ -n "$ID" ] || fail "test: the cell wrote no data"
list=$(for h in a b c; do if [ $h = $H ]; then printf '{"file":"%s.host","drain":true},' $h; else printf '{"file":"%s.host"},' $h; fi; done | sed 's/,$//')
tissue_store "$list"            # the holder is to be emptied: a planned move
moved() { [ "$(count store)" = 1 ] && ! on $H ps | grep -q '^store-'; }
until_true "a b c" moved || fail "store did not move off $H"
N=$(where store | tr -d ' ')
[ "$(cat "$(idfile $N)" 2>/dev/null)" = "$ID" ] && pass "when its host is drained, a cell with data restarts elsewhere with its data: nothing lost" || fail "data on $N: $(cat "$(idfile $N)" 2>&1), want $ID"
grep -rqa "$ID" ledger && fail "the snapshot in the ledger is readable"
pass "the snapshot in the ledger is encrypted"
on $N log | grep -q 'restored volumes from the snapshot' && pass "the restore is in the new host's signed record" || fail "no record of the restore"

if [ $ROOT = yes ]; then
  # A crash: the holder simply stops. Only a volume with a size can be copied while its capsule runs.
  release vault "$STORE" ',"volumes":[{"name":"data","path":"/data","size":"16M"}]'
  cat > tissue.json <<JSON
{"name":"fast","lease":4,"cells":{"vault":{"root":true,"standby":"warm","snapshot":"30s"}},
 "hosts":[{"file":"a.host"},{"file":"b.host"},{"file":"c.host"}]}
JSON
  publish
  vup() { [ "$(count vault)" = 1 ] && [ -n "$(ls ledger/tissue/snapshots/vault 2>/dev/null)" ]; }
  until_true "a b c" vup || fail "vault did not come up and ship a snapshot"
  H=$(where vault | tr -d ' ')
  ID=$(cat "$W/$H/data/volumes/vault/data/data/id")
  [ -n "$ID" ] || fail "test: vault wrote no data"
  pass "a running cell with a sized volume ships a snapshot of it without stopping"
  others=$(echo "a b c" | sed "s/$H//")
  elsewhere() { for h in $others; do on $h ps | grep -q '^vault-' && return 0; done; return 1; }
  until_true "$others" elsewhere || fail "nobody took vault over after its host went silent"
  N=$(for h in $others; do on $h ps | grep -q '^vault-' && echo $h; done; true)
  [ "$(cat "$W/$N/data/volumes/vault/data/data/id" 2>/dev/null)" = "$ID" ] && pass "when its host goes silent, the cell comes back on another with the data of its last snapshot" || fail "data on $N after a crash: $(cat "$W/$N/data/volumes/vault/data/data/id" 2>&1), want $ID"
fi
for h in a b c; do on $h log >/dev/null 2>&1 || fail "the record of host $h does not verify"; done
pass "every host's record is intact"
echo "all takeover checks passed"
