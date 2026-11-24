#!/bin/sh
# Cells and receptors, on a Linux host, as root or not:
#   sudo sh test/cell.sh /usr/local/bin/capsule bin/sock-linux-arm64
#   sh test/cell.sh /usr/local/bin/capsule bin/sock-linux-arm64
# A "store" cell offers named services; other cells use them. The second
# argument is the helper built from test/sock. Needs busybox-static, and
# reaches the drand beacon for ticks if it can.
set -eu
CAPSULE=$(realpath "$1")
SOCK=$(realpath "$2")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d)
export CAPSULE_CONFIG="$W/conf" CAPSULE_DATA="$W/data" CAPSULE_RUN="$W/run"
export CAPSULE_PSK_TICKS=5 # tunnels change their post-quantum secret every 15 seconds, all through this test
cleanup() {
  set +e # clearing up must not turn a passed run into a failure
  for id in $("$CAPSULE" ps | grep -E '^(store|web|cli|rogue)-' | cut -d' ' -f1); do "$CAPSULE" kill "$id"; done
  pkill -P $$ 2>/dev/null || true
  wait
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
mkdir cards grants nogrants shortgrants

fail() { echo "FAIL: $1"; [ -f store.log ] && sed 's/^/  store: /' store.log; exit 1; }
pass() { echo "ok   $1"; }

"$CAPSULE" keygen dev
"$CAPSULE" keygen other
card() { # $1 = name, $2 = instance label, $3 = endpoint
  key=$("$CAPSULE" identity -instance "$2" "$1" | grep ^key | tr -s ' ' | cut -d' ' -f2)
  kem=$("$CAPSULE" identity -instance "$2" "$1" | grep ^kem | tr -s ' ' | cut -d' ' -f2)
  "$CAPSULE" card -key dev.key -name "$1" -mesh-key "$key" -kem "$kem" ${3:+-endpoint "$3"} > "cards/$1-$2.card"
}
cell() { # $1 = directory, $2 = name, $3 = shell script, $4 = offers and needs
  mkdir -p "$1/rootfs/bin"
  cp "$BUSYBOX" "$1/rootfs/bin/busybox"
  cp "$SOCK" "$1/rootfs/bin/sock"
  for a in sh echo nc sleep cat head ls; do ln -sf busybox "$1/rootfs/bin/$a"; done
  printf '#!/bin/sh\ncat /tmp/id\n' > "$1/rootfs/bin/reply"
  printf '#!/bin/sh\necho secret\n' > "$1/rootfs/bin/secret"
  printf '#!/bin/sh\nread line; echo "$line"\n' > "$1/rootfs/bin/first"
  printf '#!/bin/sh\necho held\nsleep 100\n' > "$1/rootfs/bin/hold"
  chmod 755 "$1/rootfs/bin/reply" "$1/rootfs/bin/secret" "$1/rootfs/bin/first" "$1/rootfs/bin/hold"
  cat > "$1/capsule.json" <<JSON
{"name":"$2","command":["/bin/sh","-c","$3"],"network":"cell",$4,"limits":{"memory":"64M","pids":256}}
JSON
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
}
run() { dir=$1; shift; "$CAPSULE" run -trust "$W/dev.pub" -peers cards "$@" "$dir" 2>&1; }

cell store store 'cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 5432 -e /bin/reply & nc -ll -p 6000 -e /bin/secret & nc -ll -p 7000 -e /bin/first & nc -ll -p 6100 -e /bin/hold & sock serve4 7100 ipv4-only & sock udp-serve 5300 secret & sock udp-serve 5301 secret & sock serve /run/cell/offer/files from-a-socket & sleep 300' \
  '"offers":[{"name":"db","to":["web","cli"],"port":5432},
             {"name":"vault","to":["web"],"port":6000,"grant":true},
             {"name":"who","to":["web"],"port":7000,"proxy_protocol":true},
             {"name":"hold","to":["web"],"port":6100,"grant":true},
             {"name":"time","to":["web"],"port":5300,"udp":true},
             {"name":"utime","to":["web"],"port":5301,"udp":true,"grant":true},
             {"name":"legacy","to":["web"],"port":7100},
             {"name":"files","to":["web"]}]'
NEEDS='"needs":[{"name":"db","from":"store","port":5432},{"name":"vault","from":"store","port":6000},{"name":"who","from":"store","port":7000},{"name":"files","from":"store"},{"name":"legacy","from":"store","port":7100},{"name":"hold","from":"store","port":6100},{"name":"time","from":"store","port":5300,"udp":true},{"name":"utime","from":"store","port":5301,"udp":true}]'
TWELVE='1 2 3 4 5 6 7 8 9 10 11 12'

card store 1 127.0.0.1:51911
card store 2 127.0.0.1:51912
card web "" ""
card cli "" ""
card rogue "" ""
"$CAPSULE" run -trust dev.pub -peers cards -instance 1 -listen 51911 store >store.log 2>&1 &
"$CAPSULE" run -trust dev.pub -peers cards -instance 2 -listen 51912 store >>store.log 2>&1 &
# Wait until both instances are serving: starting includes asking the beacon for the tick.
cell ready web 'nc -w 2 db 5432 || echo blocked' "$NEEDS"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 2
  [ "$("$CAPSULE" ps | grep -c '^store-')" = 2 ] && run ready | grep -Eq '^[0-9a-f-]{36}$' && break
done
sleep 2

# ---- reaching a need ----
cell web1 web "for i in $TWELVE; do nc -w 3 db 5432 || echo blocked; done" "$NEEDS"
all=$(run web1)
out=$(echo "$all" | grep -v '^capsule: cell\|^DBG')
ids=$(echo "$out" | sort -u)
echo "$ids" | grep -q blocked && fail "web could not use the db receptor by name (got: $out)"
[ "$(echo "$out" | wc -l)" = 12 ] || fail "want 12 answers from db, got: $out"
pass "a need is reached by its name and the port the application expects"
[ "$(echo "$ids" | wc -l)" = 2 ] || fail "12 connections reached $(echo "$ids" | wc -l) instance(s) of store, want 2: $(echo "$all" | grep -a DBG)"
pass "connections are spread over both instances of the offering cell"

cell web2 web 'sock dial /run/cell/need/db; sock dial /run/cell/need/files' "$NEEDS"
out=$(run web2 | grep -v '^capsule: cell\|^DBG')
echo "$out" | head -1 | grep -Eq '^[0-9a-f-]{36}$' || fail "the socket /run/cell/need/db did not lead to db (got: $out)"
pass "a need is reached through its socket file, with no port at all"
echo "$out" | tail -1 | grep -q from-a-socket || fail "an offer served on a socket file was not reached (got: $out)"
pass "an offer is served from a socket file: neither side opened a port"

# ---- the kernel carries it where it can, and the supervisor where it must ----
if [ "$(id -u)" = 0 ]; then
  id=$("$CAPSULE" ps | grep -E '^store-' | head -1 | cut -d' ' -f1)
  DB=$("$CAPSULE" inspect store | grep 'offers.*db ' | grep -o 'mesh port [0-9]*' | cut -d' ' -f3)
  LEGACY=$("$CAPSULE" inspect store | grep 'offers.*legacy ' | grep -o 'mesh port [0-9]*' | cut -d' ' -f3)
  for _ in 1 2 3 4 5 6 7 8; do # the supervisor looks for listeners every two seconds
    rules=$(nsenter --net="$CAPSULE_RUN/$id.netns" nft list chain inet capsule arrive 2>&1 || true)
    echo "$rules" | grep -q "dport $DB dnat" && break
    sleep 1
  done
  echo "$rules" | grep -q "dport $DB dnat" || fail "the kernel is not delivering db to an application that listens on every address: $rules"
  echo "$rules" | grep -q "dport $LEGACY " && fail "the kernel was told to deliver to an application that listens on IPv4 only: $rules"
  pass "port to port, the kernel carries a receptor's traffic with no process in between"
fi
cell web9 web 'nc -w 3 legacy 7100 || echo blocked' "$NEEDS"
out=$(run web9)
echo "$out" | grep -q ipv4-only || fail "an application listening on IPv4 only was not reached (got: $out)"
pass "an application that listens on IPv4 only is still reached, through the supervisor"

# ---- the application cannot go beyond what it needs ----
ADDR=$("$CAPSULE" identity -instance 1 store | grep ^address | tr -s ' ' | cut -d' ' -f2)
PORT=$("$CAPSULE" inspect store | grep 'offers.*files ' | grep -o 'mesh port [0-9]*' | cut -d' ' -f3)
[ -n "$PORT" ] || fail "inspect does not show where a receptor is carried"
cell web3 web "nc -w 3 $ADDR $PORT 2>/dev/null || echo blocked; nc -w 3 $ADDR 5432 2>/dev/null || echo blocked; nc -w 3 db 5432 >/dev/null && echo through" '"needs":[{"name":"db","from":"store","port":5432}]'
out=$(run web3 | grep -v '^capsule: cell\|^DBG')
[ "$(echo "$out" | grep -c blocked)" = 2 ] || fail "the application reached a receptor it does not need, or another cell's own port (got: $out)"
echo "$out" | tail -1 | grep -q through || fail "test expected the receptor it does need to keep working (got: $out)"
pass "the application can send only to the receptors it needs, and nowhere else on the mesh"

# ---- who may use what ----
cell cli cli 'nc -w 3 db 5432 >/dev/null && echo db-ok; nc -w 3 vault 6000 || echo blocked' \
  '"needs":[{"name":"db","from":"store","port":5432},{"name":"vault","from":"store","port":6000}]'
out=$(run cli -grants grants)
echo "$out" | grep -q db-ok || fail "cli could not use db, which is offered to it (got: $out)"
echo "$out" | grep -q secret && fail "cli used vault, which is not offered to it (got: $out)"
pass "a receptor answers only the cells it is offered to"
cell rogue rogue 'nc -w 3 db 5432 || echo blocked' '"needs":[{"name":"db","from":"store","port":5432}]'
out=$(run rogue)
echo "$out" | grep -Eq '^[0-9a-f-]{36}$' && fail "a cell that store does not name used its receptor (got: $out)"
pass "a cell the offer does not name cannot use it, whatever its own manifest says"

# ---- the caller's identity reaches the application ----
WEBADDR=$("$CAPSULE" identity web | grep ^address | tr -s ' ' | cut -d' ' -f2)
cell web4 web 'nc -w 3 who 7000 || echo blocked' "$NEEDS"
out=$(run web4)
echo "$out" | grep -q "^PROXY TCP6 $WEBADDR " || fail "the application was not told who is calling (got: $out, want address $WEBADDR)"
pass "proxy_protocol: the application is told which cell is calling"

# ---- grants and ticks ----
"$CAPSULE" tick > tick.out || fail "capsule tick failed"
grep -q 'signed by the drand beacon' tick.out && TICKS=beacon || TICKS=clock
cell web5 web 'nc -w 3 vault 6000 || echo blocked' "$NEEDS"
out=$(run web5 -grants nogrants)
echo "$out" | grep -q secret && fail "a receptor that needs a grant answered a caller without one"
echo "$out" | grep -q "needs a grant" || fail "the caller was not told why it was refused (got: $out)"
pass "grant: a caller without one is refused, and told why"

"$CAPSULE" grant -key other.key -receptor vault -of store -to web > nogrants/untrusted.grant 2>/dev/null
out=$(run web5 -grants nogrants)
echo "$out" | grep -q secret && fail "a grant signed by an untrusted key was accepted"
pass "grant: one signed by a key the offering host does not trust is refused"
rm nogrants/untrusted.grant

"$CAPSULE" grant -key dev.key -receptor vault -of store -to cli > nogrants/cli.grant 2>/dev/null
"$CAPSULE" grant -key dev.key -receptor db -of store -to web > nogrants/db.grant 2>/dev/null
out=$(run web5 -grants nogrants)
echo "$out" | grep -q secret && fail "a grant for another cell or another receptor was accepted"
pass "grant: one made out to another cell, or for another receptor, does not count"

"$CAPSULE" grant -key dev.key -receptor vault -of store -to web -for 9s > grants/vault.grant 2>/dev/null
out=$(run web5 -grants grants)
echo "$out" | grep -q secret || fail "a caller holding a grant in date was refused (got: $out)"
pass "grant: a caller holding one in date is let in (ticks from the $TICKS)"
sleep 16
out=$(run web5 -grants grants)
echo "$out" | grep -q secret && fail "an expired grant was accepted"
echo "$out" | grep -q "expired" || fail "the caller was not told its grant had expired (got: $out)"
pass "grant: it stops working by itself when its ticks run out"
"$CAPSULE" grant -key dev.key -receptor vault -of store -to web -for 1h > grants/vault.grant 2>/dev/null
out=$(run web5 -grants grants)
echo "$out" | grep -q secret || fail "a renewed grant was not accepted (got: $out)"
pass "grant: renewing it lets the caller back in, with nothing restarted"

# ---- a connection does not outlive its grant ----
"$CAPSULE" grant -key dev.key -receptor hold -of store -to web -for 9s > shortgrants/hold.grant 2>/dev/null
cell web6 web 'nc hold 6100; echo ended' "$NEEDS"
began=$(date +%s)
out=$(run web6 -grants shortgrants)
took=$(( $(date +%s) - began ))
echo "$out" | grep -q held || fail "test expected the held connection to open (got: $out)"
[ "$took" -lt 60 ] || fail "a connection stayed open ${took}s, long after its 9s grant ran out"
grep -q "its grant has run out" store.log || fail "the connection ended, but not because its grant ran out"
pass "grant: an open connection is closed when its grant runs out (after ${took}s)"

# ---- datagrams ----
cell web7 web 'sock udp-ask time:5300; echo --; sock udp-ask utime:5301' "$NEEDS"
out=$(run web7 -grants nogrants)
echo "$out" | sed -n '1,/^--$/p' | grep -q secret || fail "a datagram receptor did not answer (got: $out)"
pass "udp: datagrams go out and come back through a receptor"
echo "$out" | sed -n '/^--$/,$p' | grep -q secret && fail "a datagram receptor that needs a grant answered a caller without one (got: $out)"
"$CAPSULE" grant -key dev.key -receptor utime -of store -to web -for 1h > grants/utime.grant 2>/dev/null
out=$(run web7 -grants grants)
echo "$out" | sed -n '/^--$/,$p' | grep -q secret || fail "a datagram caller holding a grant was refused (got: $out)"
pass "udp: a receptor that needs a grant answers only a caller holding one"

# ---- a cell with only socket files cannot make a network socket at all ----
cell web8 web 'nc -w 2 127.0.0.1 9; sock dial /run/cell/need/files' '"needs":[{"name":"files","from":"store"}]'
out=$(run web8)
echo "$out" | grep -qi "not supported" || fail "a sockets-only cell was able to create a network socket (got: $out)"
echo "$out" | grep -q from-a-socket || fail "a sockets-only cell could not use its socket file (got: $out)"
pass "a cell whose openings are all socket files cannot create any network socket"

# ---- tunnels carry a post-quantum secret, and it changes on schedule ----
[ "$(ls cards/*.psk 2>/dev/null | wc -l)" -ge 2 ] || fail "no post-quantum secrets were published for the tunnels: $(ls cards)"
grep -q MARKER cards/*.psk && fail "test is broken"
if [ "$(id -u)" = 0 ] && command -v wg >/dev/null; then
  id=$("$CAPSULE" ps | grep -E '^store-' | head -1 | cut -d' ' -f1)
  keys=$(nsenter --net="$CAPSULE_RUN/$id.netns" wg show wg0 preshared-keys | grep -vc '(none)' || true)
  [ "$keys" -ge 1 ] || fail "the kernel's tunnel has no preshared key set"
fi
before=$(cat cards/*.psk | cksum)
sleep 17
out=$(run web1)
[ "$(cat cards/*.psk | cksum)" != "$before" ] || fail "the tunnels' post-quantum secrets did not change with the epoch"
echo "$out" | grep -q blocked && fail "connections failed after the tunnels' secrets changed (got: $out)"
pass "tunnels mix in an ML-KEM secret that is replaced every epoch, without losing connections"

# ---- ticks when the beacon cannot be reached ----
mkdir offline
echo 99999999999 > offline/tick
out=$(CAPSULE_DATA="$W/offline" CAPSULE_DRAND=http://127.0.0.1:9 "$CAPSULE" tick)
echo "$out" | grep -q "host's clock" || fail "tick did not say it fell back on the host's clock (got: $out)"
[ "$(echo "$out" | cut -d' ' -f1)" -ge 99999999999 ] || fail "without the beacon, the tick went back before one already proven here (got: $out)"
pass "ticks: without the beacon they come from the host's clock, and never go back"

# ---- nothing left behind ----
for id in $("$CAPSULE" ps | grep -E '^store-' | cut -d' ' -f1); do "$CAPSULE" kill "$id"; done
wait
[ -z "$(ls -A "$CAPSULE_RUN" 2>/dev/null)" ] || fail "run state left behind: $(ls -A "$CAPSULE_RUN")"
pass "socket files and run state are gone when the cells stop"
echo "all checks passed"
