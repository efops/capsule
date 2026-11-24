#!/bin/sh
# Mesh networking check on a Linux host: sudo sh test/mesh.sh /usr/local/bin/capsule
# Runs instances of a "web" capsule and connects to them from others on the same host.
# Needs busybox-static and the nft tool (package nftables) on the host.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data"
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  for id in $("$CAPSULE" ps | grep -E '^(web|cli|probe|rogue)-' | cut -d' ' -f1); do "$CAPSULE" kill "$id"; done
  pkill -P $$ 2>/dev/null || true
  wait
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
mkdir all one # card directories: every instance, and only the first web instance

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

"$CAPSULE" keygen dev
"$CAPSULE" keygen other
card() { # $1 = signing key, $2 = name, $3 = instance label, $4 = endpoint, $5 = output file
  key=$("$CAPSULE" identity -instance "$3" "$2" | grep ^key | tr -s ' ' | cut -d' ' -f2)
  "$CAPSULE" card -key "$1" -name "$2" -mesh-key "$key" ${4:+-endpoint "$4"} > "$5"
}
capsule() { # $1 = name, $2 = shell script, $3 = peers
  mkdir -p "$1/rootfs/bin"
  cp "$BUSYBOX" "$1/rootfs/bin/busybox"
  for a in sh echo nc sleep cat head; do ln -sf busybox "$1/rootfs/bin/$a"; done
  printf '#!/bin/sh\ncat /tmp/id\nsleep 14\n' > "$1/rootfs/bin/slow"; chmod 755 "$1/rootfs/bin/slow"
  printf '#!/bin/sh\ncat /tmp/id\n' > "$1/rootfs/bin/reply"
  printf '#!/bin/sh\necho secret\n' > "$1/rootfs/bin/secret"
  chmod 755 "$1/rootfs/bin/reply" "$1/rootfs/bin/secret"
  cat > "$1/capsule.json" <<JSON
{"name":"$1","command":["/bin/sh","-c","$2"],"network":"mesh","mesh":{"peers":$3},"limits":{"memory":"64M","pids":256}}
JSON
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
}
run() { dir=$1; shift; "$CAPSULE" run -trust "$W/dev.pub" "$@" "$dir" 2>&1; }

# Each web instance answers with its own id. cli and probe may reach 8080; nobody may reach 9090.
capsule web 'cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 8080 -e /bin/reply & nc -ll -p 8082 -e /bin/slow & nc -ll -p 9090 -e /bin/secret & sleep 300' \
  '[{"name":"cli","in":[8080,8082],"in_udp":[5353]},{"name":"probe","in":[8080]}]'
TWELVE='1 2 3 4 5 6 7 8 9 10 11 12'
MANY="$TWELVE $TWELVE"
capsule cli "for i in $TWELVE; do nc -w 3 web 8080 || echo blocked; done; nc -w 3 web 9090 || echo blocked" '[{"name":"web","out":[8080]}]'
capsule probe 'nc -w 3 web 8080 || echo blocked; nc -w 3 web 9090 || echo blocked' '[{"name":"web","out":[8080,9090]}]'
capsule rogue 'nc -w 3 web 8080 || echo blocked' '[{"name":"web","out":[8080]}]'

card dev.key web 1 127.0.0.1:51901 all/web-1.card
card dev.key web 2 127.0.0.1:51902 all/web-2.card
card dev.key cli "" "" all/cli.card
card dev.key probe "" "" all/probe.card
card dev.key rogue "" "" all/rogue.card       # a real card, but web's manifest does not name rogue
card other.key cli evil "" all/cli-evil.card  # claims to be cli, signed by a key nobody trusts
cp all/web-1.card one/

run web -peers all -instance 1 -listen 51901 &
"$CAPSULE" run -trust dev.pub -peers all -instance 2 -listen 51902 web >/dev/null 2>&1 & WEB2=$!
sleep 2

out=$(run cli -peers all)
ids=$(echo "$out" | head -12 | sort -u)
echo "$ids" | grep -q blocked && fail "cli could not reach web:8080 by name (got: $out)"
pass "named peer connects on an allowed port over WireGuard"
[ "$(echo "$ids" | wc -l)" = 2 ] || fail "12 connections reached $(echo "$ids" | wc -l) instance(s), want 2"
pass "kernel spreads connections across both instances"
echo "$out" | tail -1 | grep -q blocked || fail "cli reached web:9090, which its own manifest does not allow (got: $out)"
pass "sender's manifest blocks a port it does not declare"

out=$(run probe -peers all)
echo "$out" | head -1 | grep -q blocked && fail "probe could not reach web:8080 (got: $out)"
echo "$out" | tail -1 | grep -q blocked || fail "probe reached web:9090, which web does not allow (got: $out)"
pass "receiver's manifest blocks a port the sender allowed itself"

out=$(run rogue -peers all)
echo "$out" | grep -q blocked || fail "rogue reached web without being named in its manifest (got: $out)"
pass "capsule the receiver does not name cannot connect"

out=$(run cli -peers all -instance evil)
[ "$(echo "$out" | grep -c blocked)" = 13 ] || fail "instance with an untrusted card reached web (got: $out)"
pass "instance whose card is signed by an untrusted key cannot connect"

# The caller's manifest chooses how connections are spread over the two instances.
balanced() { # $1 = balance setting; prints how many of 12 connections each instance received
  capsule cli "for i in $TWELVE; do nc -w 3 web 8080 || echo blocked; done" "[{\"name\":\"web\",\"out\":[8080],\"balance\":\"$1\"}]"
  run cli -peers all | sort | uniq -c | tr -s ' ' | cut -d' ' -f2,3
}
[ "$(balanced round-robin | cut -d' ' -f1 | tr '\n' ' ')" = "6 6 " ] || fail "round-robin did not give each instance exactly half: $(balanced round-robin)"
pass "balance round-robin: 12 connections, exactly 6 to each instance"
first=$(balanced failover); again=$(balanced failover)
[ "$(echo "$first" | wc -l)" = 1 ] && [ "$first" = "$again" ] || fail "failover did not keep to one instance: $first / $again"
pass "balance failover: every connection to the same one instance"
[ "$(balanced sticky | wc -l)" = 1 ] || fail "sticky spread one caller over several instances: $(balanced sticky)"
pass "balance sticky: this caller always reaches the same instance"

# Least connections: four connections that each stay open, started four seconds apart.
# Port 8082 answers with the instance's id and then holds the connection for 14 seconds.
capsule cli 'for i in 1 2 3 4; do nc web 8082 > /tmp/o$i & sleep 4; done; for i in 1 2 3 4; do head -1 /tmp/o$i; done' '[{"name":"web","out":[8082],"balance":"least-connections"}]'
spread=$(run cli -peers all | sort | uniq -c | tr -s ' ' | cut -d' ' -f2 | tr '\n' ' ')
[ "$spread" = "2 2 " ] || fail "least-connections put the four held connections $spread, want 2 and 2"
pass "balance least-connections: held connections go to whichever instance has fewer"

# Scale out while a caller is running: it starts knowing one instance and is handed the second.
capsule cli "for i in $MANY; do nc -w 3 web 8080 || echo blocked; sleep 1; done" '[{"name":"web","out":[8080]}]'
run cli -peers one > live.out &
sleep 4
[ "$(sort -u live.out | wc -l)" = 1 ] || fail "caller with one card reached more than one instance"
cp all/web-2.card one/
wait $!
[ "$(sort -u live.out | wc -l)" = 2 ] || fail "caller did not start using the instance added while it ran (got: $(cat live.out))"
grep -q blocked live.out && fail "connections failed during scale-out"
pass "instance added while the caller runs starts receiving connections, no reseal or restart"

if [ "$(id -u)" = 0 ]; then # looking inside another process's network takes root
  pid=$(head -1 "$(readlink "$(ls -d /run/capsule/web-*.cg | head -1)")/cgroup.procs")
  nsenter -t "$pid" -n nft list ruleset | grep -q "udp dport 5353 accept" || fail "in_udp did not become a UDP rule"
  pass "UDP ports get their own rules"
fi

# A host that has been delegated the name registers its own instances.
SIGN=$("$CAPSULE" host | grep ^sign | tr -s ' ' | cut -d' ' -f2)
"$CAPSULE" delegate -key dev.key -host "$SIGN" web > "$CAPSULE_CONFIG/delegation"
"$CAPSULE" run -trust dev.pub -peers all -instance 3 -listen 51903 -advertise 127.0.0.1 web >/dev/null 2>&1 & WEB3=$!
sleep 4
[ "$(ls all | grep -c '^web-')" = 3 ] || fail "third instance did not publish its own card"
capsule cli "for i in $MANY; do nc -w 3 web 8080 || echo blocked; done" '[{"name":"web","out":[8080]}]'
out=$(run cli -peers all)
[ "$(echo "$out" | sort -u | wc -l)" = 3 ] || fail "24 connections reached $(echo "$out" | sort -u | wc -l) instance(s), want 3 (got: $out)"
pass "instance registers itself with a host-issued card and receives connections"
out=$(run probe -peers all -instance unvouched)
[ "$(echo "$out" | grep -c blocked)" = 2 ] || fail "host issued itself a card for a name it was not delegated (got: $out)"
pass "host cannot issue a card for a name it was not delegated"
kill -TERM $WEB3; wait $WEB3 || true
[ "$(ls all | grep -c '^web-')" = 2 ] || fail "stopped instance left its card behind"
pass "instance removes its card when it stops"

# An instance that dies without removing its card stops receiving connections.
kill -KILL $WEB2; wait $WEB2 || true
sleep 1
out=$(run cli -peers all)
echo "$out" | grep -q blocked && fail "connections were sent to a dead instance (got: $out)"
[ "$(echo "$out" | sort -u | wc -l)" = 1 ] || fail "expected only the surviving instance to answer (got: $out)"
pass "health check: a dead instance gets no connections"
[ "$("$CAPSULE" ps | grep -c '^web-')" = 1 ] || fail "capsule whose supervisor was killed is still listed"
pass "a capsule whose supervisor was killed is cleared from ps"

echo "all checks passed"
