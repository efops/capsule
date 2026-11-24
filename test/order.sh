#!/bin/sh
# Orders: operating a host without logging in to it. As root or not:
#   sudo sh test/order.sh /usr/local/bin/capsule
#   sh test/order.sh /usr/local/bin/capsule
# One machine plays the host and, with separate settings, the operator's
# workstation. Needs busybox-static, systemd and nsenter.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
W=$(mktemp -d /tmp/capsule-order.XXXXXX)
chmod 755 "$W"
HOST="CAPSULE_CONFIG=$W/host/conf CAPSULE_DATA=$W/host/data CAPSULE_RUN=$W/host/run"
OPER="CAPSULE_CONFIG=$W/oper/conf CAPSULE_DATA=$W/oper/data"
USERFLAG=--user
[ "$(id -u)" = 0 ] && USERFLAG=
host() { env $HOST "$CAPSULE" "$@"; }
oper() { env $OPER "$CAPSULE" "$@"; }
obey() { # the host looks for orders, the way its timer would
  if [ -n "$USERFLAG" ]; then
    systemd-run --user --wait --pipe --quiet --collect -E "CAPSULE_CONFIG=$W/host/conf" -E "CAPSULE_DATA=$W/host/data" -E "CAPSULE_RUN=$W/host/run" "$CAPSULE" orders
  else
    host orders
  fi
}
cleanup() {
  set +e
  systemctl $USERFLAG stop capsule-run-web.service 2>/dev/null
  for id in $(host ps | grep -E '^web-' | cut -d' ' -f1); do host kill "$id"; done
  sleep 1
  rm -rf "$W"
}
trap cleanup EXIT
cd "$W"
fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

mkdir -p host/conf/trust.d host/conf/operators.d oper/conf ledger other/conf
for k in dev op1 op2 rogue; do "$CAPSULE" keygen $k >/dev/null; done
cp dev.pub host/conf/trust.d/
cp op1.pub op2.pub host/conf/operators.d/
echo "file://$W/ledger" > host/conf/ledger
echo "file://$W/ledger" > oper/conf/ledger
echo "file://$W/ledger" > other/conf/ledger
host host -export > host.json
env CAPSULE_CONFIG="$W/other/conf" "$CAPSULE" host -export > other.json
hosthex() { ls ledger/orders | head -1; }

mkdir -p web/rootfs/bin
cp "$BUSYBOX" web/rootfs/bin/busybox
for a in sh echo sleep cat grep touch hostname; do ln -sf busybox web/rootfs/bin/$a; done
cat > web/capsule.json <<JSON
{"name":"web","command":["/bin/sleep","600"],"env":{"COLOUR":"green"},"limits":{"memory":"64M","pids":64}}
JSON
"$CAPSULE" seal -key dev.key web >/dev/null
SEAL=$(oper publish -key dev.key -trust dev.pub web | sed -n 's/^published web //p')
[ -n "$SEAL" ] || fail "could not publish the test capsule"

# send <signing key> <action...>: prints the order's id
send() { key=$1; shift; oper order -key "$key" -host host.json "$@" | sed -n 's/^sent order \(sha256:[0-9a-f]*\).*/\1/p'; }
# ask <action...>: send as op1, let the host act, print its answer
ask() { id=$(send op1.key "$@"); obey 2>/dev/null || true; oper order result "$id" 2>&1 || true; }

host orders 2>/dev/null && pass "a host with nothing waiting does nothing" || fail "orders failed with nothing waiting"

out=$(ask ps)
echo "$out" | grep -q ': ok' && echo "$out" | grep -q 'MEM LIMIT' && pass "ps order answered" || fail "ps order: $out"

out=$(ask fetch web)
echo "$out" | grep -q "installed web $SEAL" && pass "fetch order installed the release" || fail "fetch order: $out"

out=$(ask run web)
echo "$out" | grep -q 'started web-' && host ps | grep -q '^web-' && pass "run order started the capsule, and it outlived the order" || fail "run order: $out"

out=$(ask run web)
echo "$out" | grep -q 'already running' && [ "$(host ps | grep -c '^web-')" = 1 ] && pass "a second run order starts nothing more" || fail "second run: $out"

out=$(ask resize web memory=32M)
echo "$out" | grep -q 'resized 1' && host ps | grep '^web-' | grep -q '32.0M' && pass "resize order changed the limit" || fail "resize: $out $(host ps)"

out=$(ask exec web -- /bin/echo hi)
echo "$out" | grep -q 'FAILED' && echo "$out" | grep -q 'does not take exec orders' && pass "exec is refused until the host allows it" || fail "exec by default: $out"

printf 'exec 2   # two operators\n* 1\n' > host/conf/orders
out=$(ask exec web -- /bin/echo hi)
echo "$out" | grep -q 'signed by 1 of' && pass "exec with one signature of the two required is refused" || fail "exec one signer: $out"

oper order -key op1.key -host host.json -o exec.order exec web -- /bin/sh -c 'echo inside-$(hostname)-$COLOUR; grep -E "CapEff|Seccomp:|NoNewPrivs" /proc/self/status; touch /x 2>&1; cat /proc/1/cmdline | tr "\0" " "' >/dev/null
oper order sign -key op2.key exec.order >/dev/null
id=$(oper order send exec.order | sed -n 's/^sent order \(sha256:[0-9a-f]*\).*/\1/p')
cp "ledger/orders/$(hosthex)/${id#sha256:}" saved.order
obey 2>/dev/null || true
out=$(oper order result "$id" 2>&1 || true)
echo "$out" | grep -q 'inside-web-green' && pass "exec order with both signatures ran inside the capsule" || fail "exec: $out"
echo "$out" | grep -q 'CapEff:.0000000000000000' && echo "$out" | grep -q 'Seccomp:.2' && echo "$out" | grep -q 'NoNewPrivs:.1' \
  && pass "the command had no capabilities and the capsule's system call filter" || fail "exec confinement: $out"
echo "$out" | grep -qi 'read-only' && echo "$out" | grep -q '/bin/sleep 600' && pass "it saw the capsule's read-only root and its processes" || fail "exec view: $out"
host ps | grep '^web-' | awk '{exit !($2 == 1)}' && pass "nothing of the command is left in the capsule" || fail "left behind: $(host ps)"

grep -rq 'inside-web' ledger && fail "the ledger holds a result in the clear"
pass "results in the ledger are sealed"
out=$(env CAPSULE_CONFIG="$W/other/conf" CAPSULE_DATA="$W/oper/data" "$CAPSULE" order result "$id" 2>&1 || true)
echo "$out" | grep -q 'sealed to another machine' && pass "another machine cannot read the result" || fail "result elsewhere: $out"

# The same order put back in the ledger is not carried out twice.
before=$(host log | grep -c "$id" || true)
mkdir -p "ledger/orders/$(hosthex)"; cp saved.order "ledger/orders/$(hosthex)/${id#sha256:}"
obey 2>/dev/null || true
[ "$before" = 1 ] && [ "$(host log | grep -c "$id")" = 1 ] && pass "a replayed order is not carried out again" || fail "replay: before=$before after=$(host log | grep -c "$id")"

out=$(id=$(send rogue.key ps); obey 2>/dev/null || true; oper order result "$id" 2>&1 || true)
echo "$out" | grep -q 'signed by 0 of' && pass "an order from a key that is not an operator is refused" || fail "rogue: $out"
host log | grep -q 'by .*: failed: signed by 0' && fail "an outsider's order reached the host's record"
pass "and leaves nothing on the host's record"

# An order for another host, copied under this host's name.
id=$(oper order -key op1.key -host other.json stop web | sed -n 's/^sent order \(sha256:[0-9a-f]*\).*/\1/p')
mine=$(host host | sed -n 's/^id *//p')
minehex=$(ls ledger/orders | while read d; do [ -f "ledger/orders/$d/${id#sha256:}" ] || echo "$d"; done | head -1)
[ -n "$minehex" ] || minehex=$(echo "$mine" | base64 -d | od -An -tx1 | tr -d ' \n')
mkdir -p "ledger/orders/$minehex"
cp ledger/orders/*/"${id#sha256:}" "ledger/orders/$minehex/" 2>/dev/null || true
obey 2>/dev/null || true
host ps | grep -q '^web-' && [ ! -e "ledger/receipts/${id#sha256:}/$minehex" ] && pass "an order addressed to another host is ignored" || fail "misaddressed order was acted on"

# An order altered in the ledger no longer matches its name.
id=$(send op1.key stop web)
sed -i 's/"action":"stop"/"action":"ps"/' "ledger/orders/$minehex/${id#sha256:}"
obey 2>/dev/null || true
host ps | grep -q '^web-' && [ ! -e "ledger/receipts/${id#sha256:}/$minehex" ] && pass "an order altered in the ledger is ignored" || fail "altered order was acted on"

id=$(send op1.key -for 3s ps)
sleep 8
obey 2>/dev/null || true
out=$(oper order result "$id" 2>&1 || true)
echo "$out" | grep -q 'lapsed' && pass "an order is refused once its span of ticks is over" || fail "lapsed: $out"

out=$(oper order -key op1.key -host host.json sh -c id 2>&1 || true)
echo "$out" | grep -q 'is not an action' && pass "there is no order that runs a command on the host" || fail "free-form action: $out"

out=$(ask stop web)
echo "$out" | grep -q 'stopped web' && ! host ps | grep -q '^web-' && pass "stop order stopped the capsule" || fail "stop: $out"

out=$(ask revoke "$SEAL")
echo "$out" | grep -q ': ok' || fail "revoke: $out"
out=$(ask run web)
echo "$out" | grep -q 'FAILED' && echo "$out" | grep -qi 'revoked' && ! host ps | grep -q '^web-' && pass "after a revoke order, a run order is refused" || fail "run after revoke: $out"

# -wait: the operator waits while the host's timer does its round.
( sleep 2; obey 2>/dev/null ) &
out=$(oper order -key op1.key -host host.json -wait 20s log 5 2>&1 || true)
wait
echo "$out" | grep -q '"event":"order"' && pass "log order returned the host's record, waited for with -wait" || fail "log -wait: $out"

host log >/dev/null 2>&1 && pass "the host's record, orders included, is intact" || fail "the host's log does not verify"
echo "all order checks passed"
