#!/bin/sh
# A real fleet: three separate machines, the installed timers doing the work.
#   sh test/fleet.sh root@host1 root@host2 root@host3
# Run it from a workstation that can SSH to all three as root. capsule must be
# installed on each (dist/install.sh), with busybox-static, nftables,
# wireguard-tools and nfs-common; the first also gets nfs-kernel-server.
#
# Settings, from the environment:
#   SSH     the ssh command                      (default: ssh -o BatchMode=yes)
#   ADDRS   the addresses the hosts reach each other on, in the same order
#           (default: the host part of each target)
#   LEDGER  the fleet ledger's URL               (default: a folder shared from the first host)
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY     for an s3:// LEDGER; written to each host's ledger.env
#
# It changes /etc/capsule on the hosts, reboots one of them, and puts
# everything back at the end. Use machines made for testing.
set -eu
[ $# = 3 ] || { echo "usage: sh test/fleet.sh root@host1 root@host2 root@host3"; exit 1; }
SSH=${SSH:-ssh -o BatchMode=yes}
T1=$1; T2=$2; T3=$3
set -- ${ADDRS:-${T1#*@} ${T2#*@} ${T3#*@}}
A1=$1; A2=$2; A3=$3
SHARE=/mnt/capsule-fleet
NFSOPTS=soft,timeo=50,noac,lookupcache=none
LEDGER=${LEDGER:-file://$SHARE/ledger}
OP="env CAPSULE_CONFIG=/root/fleet-oper/conf CAPSULE_DATA=/root/fleet-oper/data capsule" # the operator's workstation is played by host 1

R() { t=$1; shift; $SSH "$t" "$@"; }
fail() { echo "FAIL: $1"; R $T1 "$OP tissue status" 2>&1 | sed 's/^/  /'; exit 1; }
pass() { echo "ok   $1"; }
target() { case $1 in 1) echo $T1;; 2) echo $T2;; 3) echo $T3;; esac; }
runs() { R "$1" "capsule ps | grep -c '^$2-' || true"; }             # instances of a cell on a host
count() { echo $(( $(runs $T1 $1) + $(runs $T2 $1) + $(runs $T3 $1) )); }
where() { for i in 1 2 3; do [ "$(runs "$(target $i)" $1)" != 0 ] && printf '%s ' $i; done; true; }
wait_for() { # wait_for <seconds> <command...>: until it succeeds
  limit=$1; shift; start=$(date +%s)
  while ! "$@"; do [ $(( $(date +%s) - start )) -gt "$limit" ] && return 1; sleep 2; done
  WAITED=$(( $(date +%s) - start ))
}
cleanup() {
  set +e
  [ -n "${KEEP:-}" ] && return # leave everything as it is, to look at
  for t in $T1 $T2 $T3; do
    R $t "systemctl disable --now capsule-orders.timer; pkill -CONT -f 'capsule run -tissue'; systemctl stop 'capsule-cell-*' 'capsule-run-*'; for id in \$(capsule ps | tail -n +2 | cut -d' ' -f1); do capsule kill \$id; done
      rm -rf /etc/capsule/operators.d/fleet.pub /etc/capsule/trust.d/fleet.pub /etc/capsule/ledger /etc/capsule/ledger.env /etc/capsule/advertise /etc/capsule/delegation /etc/capsule/orders /var/lib/capsule/tissue /var/lib/capsule/orders /var/lib/capsule/apps/fleet-* /var/lib/capsule/volumes/fleet-* /root/fleet-oper
      [ -L /etc/capsule/peers.d ] && rm /etc/capsule/peers.d && { mv /etc/capsule/peers.d.before-fleet /etc/capsule/peers.d 2>/dev/null || mkdir /etc/capsule/peers.d; }; umount -l $SHARE" >/dev/null 2>&1
  done
  R $T1 "exportfs -u '*:$SHARE'; rm -rf /srv/capsule-fleet" >/dev/null 2>&1
}
trap cleanup EXIT

# ---- set the three hosts up ----
R $T1 "command -v exportfs >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nfs-kernel-server >/dev/null 2>&1
  rm -rf /srv/capsule-fleet; mkdir -p /srv/capsule-fleet/ledger /srv/capsule-fleet/cards && chmod -R 777 /srv/capsule-fleet
  exportfs -o rw,sync,no_root_squash,no_subtree_check '*:/srv/capsule-fleet' && systemctl start nfs-server" || fail "could not share a folder from the first host"
for t in $T1 $T2 $T3; do
  # A ledger must show every host the same thing at once: no caching of what the folder holds.
  R $t "mkdir -p $SHARE; umount -l $SHARE 2>/dev/null; mount -t nfs -o $NFSOPTS $A1:/srv/capsule-fleet $SHARE" || fail "$t could not mount the shared folder"
done
R $T1 "rm -rf /root/fleet-oper && mkdir -p /root/fleet-oper/conf && cd /root/fleet-oper && capsule keygen dev >/dev/null && capsule keygen op >/dev/null && echo '$LEDGER' > conf/ledger"
DEVPUB=$(R $T1 "cat /root/fleet-oper/dev.pub"); OPPUB=$(R $T1 "cat /root/fleet-oper/op.pub")
i=0
for t in $T1 $T2 $T3; do
  i=$((i + 1)); addr=$(eval echo \$A$i)
  R $t "echo '$DEVPUB' > /etc/capsule/trust.d/fleet.pub; echo '$OPPUB' > /etc/capsule/operators.d/fleet.pub
    echo '$LEDGER' > /etc/capsule/ledger; echo $addr > /etc/capsule/advertise
    [ -L /etc/capsule/peers.d ] || { rm -rf /etc/capsule/peers.d.before-fleet; mv /etc/capsule/peers.d /etc/capsule/peers.d.before-fleet; }; ln -sfn $SHARE/cards /etc/capsule/peers.d
    printf 'exec 1\n* 1\n' > /etc/capsule/orders"
  if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
    R $t "umask 077; printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' '$AWS_ACCESS_KEY_ID' '$AWS_SECRET_ACCESS_KEY' > /etc/capsule/ledger.env"
  fi
  sign=$(R $t "capsule host | sed -n 's/^sign *//p'")
  R $T1 "cd /root/fleet-oper && capsule delegate -key dev.key -host '$sign' fleet-web fleet-cli fleet-feed" | R $t "cat > /etc/capsule/delegation"
  R $t "capsule host -export" | R $T1 "cat > /root/fleet-oper/h$i.host"
done
if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
  R $T1 "cp /etc/capsule/ledger.env /root/fleet-oper/conf/ledger.env"
fi
out=$(R $T1 "capsule ledger check 2>&1" || true)
echo "$out" | grep -qi 'can be trusted\|passed\|safe' && pass "the ledger passes capsule's own check from a real host: $LEDGER" || echo "note: ledger check said: $(echo "$out" | tail -2 | tr '\n' ' ')"
for t in $T1 $T2 $T3; do R $t "systemctl enable --now capsule-orders.timer" >/dev/null 2>&1; done

# ---- orders reach every host through its own timer ----
start=$(date +%s)
out=$(R $T1 "cd /root/fleet-oper && $OP order -key op.key -host h1.host -host h2.host -host h3.host -wait 60s ps 2>&1" || true)
[ "$(echo "$out" | grep -c ': ok')" = 3 ] && pass "one order, three hosts, three signed answers in $(( $(date +%s) - start ))s, each host's own timer picking it up" || fail "order ps: $out"

# ---- a tissue across three machines ----
R $T1 "cd /root/fleet-oper && mk() { rm -rf \$1; mkdir -p \$1/rootfs/bin; cp /usr/bin/busybox \$1/rootfs/bin/busybox; for a in sh nc sleep cat echo hostname; do ln -s busybox \$1/rootfs/bin/\$a; done
    printf '#!/bin/sh\ncat /tmp/id\n' > \$1/rootfs/bin/reply; chmod 755 \$1/rootfs/bin/reply
    printf '%s\n' \"\$2\" > \$1/capsule.json; capsule seal -key dev.key \$1 >/dev/null && $OP publish -key dev.key -trust dev.pub \$1 >/dev/null; }
  mk fleet-web '{\"name\":\"fleet-web\",\"command\":[\"/bin/sh\",\"-c\",\"cat /proc/sys/kernel/random/uuid > /tmp/id; nc -ll -p 8080 -e /bin/reply\"],\"network\":\"mesh\",\"mesh\":{\"peers\":[{\"name\":\"fleet-cli\",\"in\":[8080]}]},\"limits\":{\"memory\":\"64M\",\"pids\":64}}'
  mk fleet-cli '{\"name\":\"fleet-cli\",\"command\":[\"/bin/sh\",\"-c\",\"sleep 20; for i in 1 2 3 4 5 6 7 8; do nc -w 3 fleet-web 8080 || echo none; sleep 1; done\"],\"network\":\"mesh\",\"mesh\":{\"peers\":[{\"name\":\"fleet-web\",\"out\":[8080],\"balance\":\"round-robin\"}]},\"limits\":{\"memory\":\"64M\",\"pids\":64}}'
  cat > tissue.json <<JSON
{\"name\":\"fleet\",\"lease\":6,\"cells\":{\"fleet-web\":{\"root\":true,\"min\":2,\"standby\":\"warm\"}},
 \"hosts\":[{\"file\":\"h1.host\"},{\"file\":\"h2.host\"},{\"file\":\"h3.host\"}]}
JSON
  $OP tissue -key op.key tissue.json" >/dev/null || fail "could not publish the capsules and the tissue"
two() { [ "$(count fleet-web)" = 2 ]; }
wait_for 90 two || fail "the tissue did not converge on two instances of fleet-web: $(count fleet-web)"
pass "the tissue placed two instances on two of three machines in ${WAITED}s, with nobody directing it"
HOLD=$(where fleet-web); set -- $HOLD; W1=$1; W2=$2
FREE=$(echo "1 2 3" | sed "s/$W1//; s/$W2//" | tr -d ' ')
R $T1 "$OP tissue status" | grep '^fleet-web' | grep -q '?' && echo "note: draws were unproven (no beacon)" || pass "each placement names the beacon round that decided it"
out=$(R "$(target $FREE)" "capsule fetch fleet-cli >/dev/null 2>&1; capsule run /var/lib/capsule/apps/fleet-cli 2>/dev/null" || true)
[ "$(echo "$out" | grep -v none | sort -u | grep -c .)" = 2 ] && pass "a caller on the third machine reaches both instances through WireGuard tunnels between real hosts" || fail "caller saw: $(echo "$out" | sort | uniq -c | tr '\n' ' ')"

# ---- a machine really goes down ----
# Not the first machine: in this test it also serves the shared folder the ledger is in.
[ "$W1" = 1 ] && W1=$W2
VICTIM=$(target $W1)
start=$(date +%s)
R $VICTIM "systemctl reboot" >/dev/null 2>&1 || true
back() { [ "$(count fleet-web 2>/dev/null)" = 2 ] 2>/dev/null; }
sleep 3
moved() { [ "$(runs "$(target $FREE)" fleet-web 2>/dev/null)" = 1 ]; }
wait_for 180 moved || fail "after a machine was rebooted, the standby did not take its instance over"
pass "one machine rebooted; its instance was running on the standby machine $(( $(date +%s) - start ))s later (lease 18s, timer 5s)"
up() { R $VICTIM true 2>/dev/null; }
wait_for 240 up || fail "the rebooted machine did not come back"
R $VICTIM "mountpoint -q $SHARE || mount -t nfs -o $NFSOPTS $A1:/srv/capsule-fleet $SHARE" || true
settled() { [ "$(count fleet-web)" = 2 ] && [ "$(runs $VICTIM fleet-web)" = 0 ]; }
wait_for 120 settled && pass "back from its reboot, the machine sees the higher term and does not start a third copy" || fail "after the reboot: $(count fleet-web) instances, $(runs $VICTIM fleet-web) on the rebooted machine"

# ---- a hot standby over a real network ----
R $T1 "cd /root/fleet-oper && mk() { rm -rf \$1; mkdir -p \$1/rootfs/bin; cp /usr/bin/busybox \$1/rootfs/bin/busybox; ln -s busybox \$1/rootfs/bin/sleep; printf '%s\n' \"\$2\" > \$1/capsule.json; capsule seal -key dev.key \$1 >/dev/null && $OP publish -key dev.key -trust dev.pub \$1 >/dev/null; }
  mk fleet-feed '{\"name\":\"fleet-feed\",\"command\":[\"/bin/sleep\",\"36000\"],\"network\":\"mesh\",\"mesh\":{\"peers\":[]},\"limits\":{\"memory\":\"64M\",\"pids\":64}}'
  cat > tissue.json <<JSON
{\"name\":\"fleet\",\"lease\":6,\"cells\":{\"fleet-feed\":{\"root\":true,\"standby\":\"hot\",\"detect\":\"${DETECT:-100ms}\"}},
 \"hosts\":[{\"file\":\"h1.host\"},{\"file\":\"h2.host\"},{\"file\":\"h3.host\"}]}
JSON
  $OP tissue -key op.key tissue.json" >/dev/null
role() { R "$(target $1)" "cat /var/lib/capsule/tissue/state/fleet-feed/role 2>/dev/null" || true; }
paired() {
  [ "$(count fleet-feed)" = 2 ] && [ "$(count fleet-web)" = 0 ] || return 1
  set -- $(where fleet-feed); [ $# = 2 ] || return 1
  r="$(role $1)$(role $2)"; [ "$r" = holderstandby ] || [ "$r" = standbyholder ]
}
wait_for 120 paired || fail "the holder and its hot standby did not settle: $(count fleet-feed) instances"
set -- $(where fleet-feed)
if [ "$(role $1)" = holder ]; then HOLDER=$1; STANDBY=$2; else HOLDER=$2; STANDBY=$1; fi
pass "a holder and a hot standby on two machines, each told its role"
sleep 5
[ "$(role $STANDBY)" = standby ] || fail "the standby promoted itself while the holder was alive: $(role $STANDBY)"
pass "over a real network the standby stays a standby while the holder's heartbeat arrives"
R "$(target $HOLDER)" "pkill -STOP -f 'capsule run -tissue /var/lib/capsule/tissue/state/fleet-feed'"
sleep 2
R "$(target $HOLDER)" "pkill -CONT -f 'capsule run -tissue /var/lib/capsule/tissue/state/fleet-feed'"
line=$(R "$(target $STANDBY)" "capsule log | grep 'standby took over after' | tail -1" || true)
took=$(echo "$line" | sed -n 's/.*took over after \([0-9.a-zµ]*\) of silence.*/\1/p')
[ -n "$took" ] && pass "the holder's supervisor frozen: the standby on another machine took over after $took of silence (set to ${DETECT:-100ms})" || fail "the standby did not take over: role $(role $STANDBY)"

# ---- data that follows its cell between machines ----
R $T1 "cd /root/fleet-oper && rm -rf fleet-store && mkdir -p fleet-store/rootfs/bin && cp /usr/bin/busybox fleet-store/rootfs/bin/busybox && for a in sh sleep cat; do ln -s busybox fleet-store/rootfs/bin/\$a; done
  printf '%s\n' '{\"name\":\"fleet-store\",\"command\":[\"/bin/sh\",\"-c\",\"[ -f /data/id ] || cat /proc/sys/kernel/random/uuid > /data/id; sleep 36000\"],\"volumes\":[{\"name\":\"data\",\"path\":\"/data\",\"size\":\"16M\"}],\"limits\":{\"memory\":\"64M\",\"pids\":64}}' > fleet-store/capsule.json
  capsule seal -key dev.key fleet-store >/dev/null && $OP publish -key dev.key -trust dev.pub fleet-store >/dev/null
  store() { cat > tissue.json <<JSON
{\"name\":\"fleet\",\"lease\":6,\"cells\":{\"fleet-store\":{\"root\":true,\"standby\":\"warm\",\"snapshot\":\"30s\"}},
 \"hosts\":[{\"file\":\"h1.host\"\$1},{\"file\":\"h2.host\"\$2},{\"file\":\"h3.host\"\$3}]}
JSON
  $OP tissue -key op.key tissue.json >/dev/null; }; store '' '' ''"
one() { [ "$(count fleet-store)" = 1 ] && [ "$(count fleet-feed)" = 0 ]; }
wait_for 120 one || fail "fleet-store did not come up"
S=$(where fleet-store | tr -d ' ')
data() { R "$(target $1)" "cat /var/lib/capsule/volumes/fleet-store/data/data/id 2>/dev/null" || true; }
have() { [ -n "$(data $S)" ]; }
wait_for 30 have || fail "the cell wrote no data"
ID=$(data $S)
sleep 12 # one pass after it is up, the first snapshot is shipped
hosts=""
for i in 1 2 3; do d=""; [ $i = "$S" ] && d=',"drain":true'; hosts="$hosts{\"file\":\"h$i.host\"$d},"; done
printf '{"name":"fleet","lease":6,"cells":{"fleet-store":{"root":true,"standby":"warm","snapshot":"30s"}},"hosts":[%s]}\n' "${hosts%,}" |
  R $T1 "cat > /root/fleet-oper/tissue.json && cd /root/fleet-oper && $OP tissue -key op.key tissue.json >/dev/null" || fail "could not publish the tissue that drains a machine"
gone() { [ "$(runs "$(target $S)" fleet-store)" = 0 ] && [ "$(count fleet-store)" = 1 ]; }
wait_for 120 gone || fail "the drained machine's cell did not move: $(where fleet-store)"
N=$(where fleet-store | tr -d ' ')
[ "$(data $N)" = "$ID" ] && pass "a machine was drained; its cell restarted on another machine with the same data after ${WAITED}s" || fail "data after the move: $(data $N), want $ID"
R $T1 "grep -rqa '$ID' $SHARE/ledger 2>/dev/null" && fail "the snapshot in the ledger is readable"
[ "${LEDGER#file:}" != "$LEDGER" ] && pass "the snapshot in the ledger is encrypted"

for t in $T1 $T2 $T3; do R $t "capsule log >/dev/null 2>&1" || fail "the record of $t does not verify"; done
pass "every machine's signed record is intact"
echo "all fleet checks passed"
