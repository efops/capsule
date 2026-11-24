#!/bin/sh
# Autoscaling check on a Linux host:
#   sudo sh test/scale.sh /usr/local/bin/capsule     everything
#        sh test/scale.sh /usr/local/bin/capsule     all but replicas on the mesh, which needs root
# Needs busybox-static. Takes about five minutes as root: it waits for load to rise and fall.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data"
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  pkill -TERM -P $$ 2>/dev/null || true
  pkill -TERM -f -- "-peers $W/all" 2>/dev/null || true # supervisors started through a shell function are not this shell's children
  sleep 2
  for id in $("$CAPSULE" ps 2>/dev/null | grep -E '^(grow|web|cli|job|front)-' | cut -d' ' -f1); do "$CAPSULE" kill "$id" 2>/dev/null || true; done
  for h in east west; do
    [ -d "$W/$h/run" ] || continue
    for id in $(CAPSULE_RUN="$W/$h/run" "$CAPSULE" ps 2>/dev/null | grep '^pool-' | cut -d' ' -f1); do CAPSULE_RUN="$W/$h/run" "$CAPSULE" kill "$id" 2>/dev/null || true; done
  done
  sleep 1
  chmod -R u+rwx "$W" 2>/dev/null; rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT
cd "$W"

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }
replicas() { "$CAPSULE" ps | grep -c "^$1-" || true; }

"$CAPSULE" keygen dev
capsule() { # $1 = name, $2 = shell script, $3 = further manifest fields
  mkdir -p "$1/rootfs/bin"
  cp "$BUSYBOX" "$1/rootfs/bin/busybox"
  for a in sh echo nc sleep cat dd date; do ln -sf busybox "$1/rootfs/bin/$a"; done
  printf '#!/bin/sh\ncat /tmp/id\n' > "$1/rootfs/bin/reply"; chmod 755 "$1/rootfs/bin/reply"
  cat > "$1/capsule.json" <<JSON
{"name":"$1","command":["/bin/sh","-c","$2"]$3}
JSON
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
}

# ---- memory: the limit grows before the capsule runs out ----
# 48M written to /tmp in one go, which counts as the capsule's memory, against a 32M limit.
capsule grow 'dd if=/dev/zero of=/tmp/big bs=1M count=48 2>/dev/null && echo survived; sleep 600' ',"limits":{"memory":"32M","pids":32},"scale":{"min":1,"max":1,"memory_max":"128M"}'
"$CAPSULE" run -trust dev.pub grow > grow.out 2>&1 & GROW=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  grep -qx survived grow.out && break
  sleep 2
done
kill -TERM $GROW; wait $GROW || true
grep -q "memory limit raised" grow.out || fail "the memory limit was never raised: $(cat grow.out)"
grep -qx survived grow.out || fail "the capsule ran out of memory despite memory_max: $(cat grow.out)"
grep -q "exited with status" grow.out && fail "the capsule was killed and restarted on the way: $(cat grow.out)"
pass "memory: a sudden 48M against a 32M limit; the limit was raised in time and nothing was killed"

# ---- a job: runs to the end once, and is not started again ----
capsule job 'echo job-done' ',"scale":{"min":1,"max":1,"restart":"on-failure"}'
out=$(timeout 30 "$CAPSULE" run -trust dev.pub job 2>&1) || fail "a finished job did not end the run cleanly: $out"
[ "$(echo "$out" | grep -c '^job-done$')" = 1 ] || fail "the job ran $(echo "$out" | grep -c '^job-done$') times, want once"
pass "restart on-failure: a job that succeeds runs once and the run ends"

# ---- a published port shared by replicas, with no mesh and no root needed ----
capsule front 'cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 8080 -e /bin/reply' ',"publish":[8080],"limits":{"memory":"32M","pids":32},"scale":{"min":2,"max":2}'
"$CAPSULE" run -trust dev.pub -publish 127.0.0.1:18095:8080 front > front.out 2>&1 & FRONT=$!
sleep 7
ask() { busybox nc -w 3 127.0.0.1 18095 2>/dev/null || echo failed; }
answers=$(for i in 1 2 3 4 5 6 7 8 9 10 11 12; do ask; done)
[ "$(echo "$answers" | sort | uniq -c | tr -s ' ' | cut -d' ' -f2 | tr '\n' ' ')" = "6 6 " ] || fail "12 connections to the published port were not shared 6 and 6: $(echo "$answers" | sort | uniq -c) $(tail -3 front.out)"
pass "published port: 12 connections shared evenly by 2 replicas"
"$CAPSULE" kill "$("$CAPSULE" ps | grep '^front-' | head -1 | cut -d' ' -f1)"
answers=$(for i in 1 2 3 4; do ask; done)
echo "$answers" | grep -q failed && fail "connections failed while one replica was down: $answers"
pass "published port: keeps answering while a replica is down"
kill -TERM $FRONT; wait $FRONT || true

if [ "$(id -u)" != 0 ]; then
  echo "all checks passed (run as root to also check replicas on the mesh)"
  exit 0
fi

# ---- replicas: more under load, fewer when it passes, restarted if they die ----
mkdir all
SIGN=$("$CAPSULE" host | grep ^sign | tr -s ' ' | cut -d' ' -f2)
"$CAPSULE" delegate -key dev.key -host "$SIGN" web > "$CAPSULE_CONFIG/delegation" # replicas issue their own cards
cli=$("$CAPSULE" identity cli | grep ^key | tr -s ' ' | cut -d' ' -f2)
"$CAPSULE" card -key dev.key -name cli -mesh-key "$cli" > all/cli.card

# Each replica answers with its own id, burns CPU for 25 seconds, then idles.
BURN='cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 8080 -e /bin/reply & end=$(( $(date +%s) + 25 )); while [ $(date +%s) -lt $end ]; do :; done; sleep 600'
capsule web "$BURN" ',"network":"mesh","mesh":{"peers":[{"name":"cli","in":[8080]}]},"limits":{"memory":"32M","cpus":0.2,"pids":32},"scale":{"min":1,"max":3,"cpu":50,"cooldown":"4s"}'
TWENTYFOUR='1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24'
capsule cli "for i in $TWENTYFOUR; do nc -w 3 web 8080 || echo blocked; done" ',"network":"mesh","mesh":{"peers":[{"name":"web","out":[8080],"balance":"round-robin"}]}'

"$CAPSULE" run -trust dev.pub -peers all -advertise 127.0.0.1 web > web.out 2>&1 & SCALER=$!
sleep 3
[ "$(replicas web)" = 1 ] || fail "did not start with one replica: $(cat web.out)"
pass "replicas: starts at the minimum, 1"

sleep 21
[ "$(replicas web)" = 3 ] || fail "under load there are $(replicas web) replicas, want 3: $(cat web.out)"
[ "$(ls all | grep -c '^web-')" = 3 ] || fail "the new replicas did not register themselves"
out=$("$CAPSULE" run -trust dev.pub -peers all cli 2>&1)
[ "$(echo "$out" | sort | uniq -c | tr -s ' ' | cut -d' ' -f2 | tr '\n' ' ')" = "8 8 8 " ] || fail "a caller did not reach all three replicas evenly: $(echo "$out" | sort | uniq -c)"
pass "replicas: grew to the maximum, 3, under load; a caller reaches all three in turn"

sleep 50
[ "$(replicas web)" = 1 ] || fail "after the load passed there are $(replicas web) replicas, want 1: $(tail -5 web.out)"
[ "$(ls all | grep -c '^web-')" = 1 ] || fail "removed replicas left their cards behind"
pass "replicas: shrank back to 1 once the load passed"

"$CAPSULE" kill "$("$CAPSULE" ps | grep '^web-' | cut -d' ' -f1)"
sleep 7
[ "$(replicas web)" = 1 ] || fail "a replica that died was not started again: $(tail -5 web.out)"
grep -q "starting it again" web.out || fail "the autoscaler did not report restarting the replica"
pass "replicas: one that dies is started again"

kill -TERM $SCALER; wait $SCALER || true
[ "$(replicas web)" = 0 ] || fail "stopping the autoscaler left replicas running"
pass "stopping it stops every replica"

# ---- across hosts: two hosts share their load and take turns ----
# Each "host" here has its own secret, data and run state, and they share a ledger and a cards directory.
on() { h=$1; shift; CAPSULE_CONFIG="$W/$h/conf" CAPSULE_DATA="$W/$h/data" CAPSULE_RUN="$W/$h/run" "$CAPSULE" "$@"; }
mkdir shared-ledger
for h in east west; do
  mkdir -p "$h/conf"
  echo "file://$W/shared-ledger" > "$h/conf/ledger"
  "$CAPSULE" delegate -key dev.key -host "$(on $h host | grep ^sign | tr -s ' ' | cut -d' ' -f2)" pool > "$h/conf/delegation"
done
LONGBURN='cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 8080 -e /bin/reply & end=$(( $(date +%s) + 50 )); while [ $(date +%s) -lt $end ]; do :; done; sleep 600'
capsule pool "$LONGBURN" ',"network":"mesh","mesh":{"peers":[{"name":"cli","in":[8080]}]},"limits":{"memory":"32M","cpus":0.2,"pids":32},"scale":{"min":0,"max":2,"cpu":50,"cooldown":"4s","fleet":true}'
capsule cli "for i in $TWENTYFOUR; do nc -w 3 pool 8080 || echo blocked; done" ',"network":"mesh","mesh":{"peers":[{"name":"pool","out":[8080],"balance":"round-robin"}]}'
on east run -trust dev.pub -peers "$W/all" -advertise 127.0.0.1 pool > east.out 2>&1 & EAST=$!
on west run -trust dev.pub -peers "$W/all" -advertise 127.0.0.1 pool > west.out 2>&1 & WEST=$!
here() { on "$1" ps | grep -c '^pool-' || true; }

sleep 14
# The host that starts from nothing says so. Exactly one of the two must have,
# however quickly the other then joins in because the first replica is busy.
[ "$(cat east.out west.out | grep -c 'across 0 replica(s)')" = 1 ] || fail "with nothing running, the first replica was started $(cat east.out west.out | grep -c 'across 0 replica(s)') times, want exactly once: $(cat east.out west.out)"
pass "fleet: with nothing running anywhere, exactly one host starts the first replica"

sleep 34
[ "$(here east)" = 2 ] && [ "$(here west)" = 2 ] || fail "under load east has $(here east) and west has $(here west) replicas, want 2 and 2: east: $(tail -n 4 east.out) west: $(tail -n 4 west.out)"
out=$("$CAPSULE" run -trust dev.pub -peers all cli 2>&1)
[ "$(echo "$out" | sort | uniq -c | tr -s ' ' | cut -d' ' -f2 | tr '\n' ' ')" = "6 6 6 6 " ] || fail "a caller did not reach all four replicas on both hosts: $(echo "$out" | sort | uniq -c)"
pass "fleet: grew to 4 replicas, spread 2 and 2 over the hosts; a caller reaches all four"

sleep 70
[ "$(( $(here east) + $(here west) ))" = 1 ] || fail "after the load passed the fleet has $(( $(here east) + $(here west) )) replicas, want 1: east: $(tail -n 4 east.out) west: $(tail -n 4 west.out)"
pass "fleet: shrank back to a single replica, and no further"
kill -TERM $EAST $WEST; wait $EAST $WEST || true
echo "all checks passed"
