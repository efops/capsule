#!/bin/sh
# Fleet ledger check on a Linux host, as root or as an ordinary user:
#   sh test/ledger.sh /usr/local/bin/capsule
# Plays two hosts sharing one ledger, once per backend: a shared directory,
# a real S3-compatible server (Versity Gateway) and a real Vault server. The two servers are
# downloaded into ~/.cache/capsule-test on first use; a backend whose server
# cannot be fetched is skipped. Needs busybox-static and curl.
set -eu
CAPSULE=$(realpath "$1")
BUSYBOX=$(command -v busybox)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/capsule-test
case $(uname -m) in aarch64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
W=$(mktemp -d)
trap 'pkill -P $$ 2>/dev/null || true; chmod -R u+rwx "$W" 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"
mkdir -p "$CACHE"

fail() { echo "FAIL: $1"; exit 1; }
pass() { echo "ok   $1"; }

"$CAPSULE" keygen dev
"$CAPSULE" keygen other
mkdir -p base/rootfs/bin
cp "$BUSYBOX" base/rootfs/bin/busybox
ln -s busybox base/rootfs/bin/sh
ln -s busybox base/rootfs/bin/echo

capsule() { # $1 = directory, $2 = policy JSON ("" for none)
  rm -rf "$1"; cp -a base "$1"
  echo "{\"name\":\"$1\",\"command\":[\"/bin/sh\",\"-c\",\"echo ran\"]${2:+,\"policy\":$2}}" > "$1/capsule.json"
  "$CAPSULE" seal -key dev.key "$1" >/dev/null
}
on() { # on <host> <capsule arguments...>: act as one of the hosts
  host=$1; shift
  CAPSULE_CONFIG="$W/$host/config" CAPSULE_DATA="$W/$host/data" "$CAPSULE" "$@" 2>&1
}
host() { # $1 = host name, $2 = ledger URL, $3 = credentials line
  mkdir -p "$1/config" "$1/data"
  echo "$2" > "$1/config/ledger"
  echo "${3:-}" > "$1/config/ledger.env"
  chmod 600 "$1/config/ledger.env"
}

scenario() { # $1 = backend name, $2 = ledger URL, $3 = credentials line
  rm -rf a b c
  host a "$2" "${3:-}"; host b "$2" "${3:-}"

  capsule "limited-$1" '{"max_runs":2,"fleet":true}'
  [ "$(on a run -trust dev.pub "limited-$1")" = ran ] || fail "$1: first fleet run refused: $(on a run -trust dev.pub "limited-$1")"
  [ "$(on b run -trust dev.pub "limited-$1")" = ran ] || fail "$1: second fleet run, on the other host, refused"
  on a run -trust dev.pub "limited-$1" | grep -q "all 2 fleet-wide runs have been used" || fail "$1: a third run was allowed"
  on b run -trust dev.pub "limited-$1" | grep -q "all 2 fleet-wide runs have been used" || fail "$1: a third run was allowed on the other host"
  pass "$1: two runs across two hosts, then refused on both"

  capsule "recalled-$1" '{"fleet":true}'
  [ "$(on b run -trust dev.pub "recalled-$1")" = ran ] || fail "$1: capsule did not run before revocation"
  on a revoke -key other.key -publish "recalled-$1" >/dev/null
  [ "$(on b run -trust dev.pub "recalled-$1")" = ran ] || fail "$1: a revocation by an untrusted key was honoured"
  on a revoke -key dev.key -publish "recalled-$1" >/dev/null
  on b run -trust dev.pub "recalled-$1" | grep -q "revoked for the whole fleet" || fail "$1: published revocation did not stop the other host"
  pass "$1: a revocation published from one host stops the capsule on the other"

  on b witness | grep -q "witnessed 1 other hosts" || fail "$1: host b did not witness host a: $(on b witness)"
  on a witness >/dev/null
  on a log -ledger | grep -q "co-signed by 1 other hosts" || fail "$1: host a's record is not co-signed: $(on a log -ledger | tail -1)"
  pass "$1: each host's record is published and co-signed by the other"

  cp a/data/log.jsonl log.bak
  rm a/data/log.jsonl a/data/published
  capsule "cover-$1" ""
  on a run -trust dev.pub "cover-$1" >/dev/null # a fresh, validly signed log in place of the real one
  on a log | grep -q "chain intact" || fail "$1: the replacement log should verify on its own"
  on a log -ledger | grep -q "rewritten after publication" || fail "$1: a rewritten log was not caught against the ledger"
  cp log.bak a/data/log.jsonl
  pass "$1: a host that rewrites its log is caught by what it published"

  host c "vault+http://127.0.0.1:1/secret/none" "VAULT_TOKEN=x" # nothing listens there
  on c run -trust dev.pub "cover-$1" | grep -qx ran || fail "$1: an ordinary capsule should still run when the ledger is unreachable"
  on c run -trust dev.pub "limited-$1" | grep -q "refusing to run" || fail "$1: a fleet capsule ran without reaching the ledger"
  pass "$1: ledger unreachable: ordinary capsules run, fleet capsules are refused"
}

fetch() { # $1 = file to create in the cache, $2 = URL
  [ -s "$CACHE/$1" ] || curl -fsSL --max-time 600 -o "$CACHE/$1.part" "$2" && mv "$CACHE/$1.part" "$CACHE/$1" 2>/dev/null || true
  [ -s "$CACHE/$1" ]
}
wait_for() { # $1 = URL that answers once the server is up
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    curl -s -o /dev/null --max-time 2 "$1" && return 0
    sleep 1
  done
  return 1
}

mkdir -p shared
scenario directory "file://$W/shared"

# An S3-compatible server: Versity Gateway, which serves a directory over the S3 API.
case $ARCH in arm64) S3ARCH=arm64 ;; *) S3ARCH=x86_64 ;; esac
if fetch s3gw.tar.gz "https://github.com/versity/versitygw/releases/download/v1.11.0/versitygw_v1.11.0_Linux_$S3ARCH.tar.gz"; then
  [ -x "$CACHE/versitygw" ] || (mkdir -p "$CACHE/s3gw" && tar -xzf "$CACHE/s3gw.tar.gz" -C "$CACHE/s3gw" && cp "$(find "$CACHE/s3gw" -type f -name versitygw | head -1)" "$CACHE/versitygw" && chmod +x "$CACHE/versitygw")
  mkdir -p "$W/s3data"
  "$CACHE/versitygw" --access capsuletest --secret capsuletest-secret --port 127.0.0.1:19000 posix "$W/s3data" >s3.log 2>&1 &
  wait_for http://127.0.0.1:19000/ || fail "the S3 server did not start: $(tail -3 s3.log)"
  curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" -u capsuletest:capsuletest-secret -X PUT http://127.0.0.1:19000/fleet >/dev/null || fail "could not create a bucket"
  scenario s3 "s3://fleet/capsule?endpoint=http://127.0.0.1:19000" "AWS_ACCESS_KEY_ID=capsuletest
AWS_SECRET_ACCESS_KEY=capsuletest-secret"
else
  echo "skip s3: could not download the S3 server"
fi

if fetch vault.zip "https://releases.hashicorp.com/vault/1.17.6/vault_1.17.6_linux_$ARCH.zip"; then
  [ -x "$CACHE/vault" ] || (cd "$CACHE" && python3 -m zipfile -e vault.zip . && chmod +x vault)
  "$CACHE/vault" server -dev -dev-root-token-id=capsuletest -dev-listen-address=127.0.0.1:18200 >vault.log 2>&1 &
  wait_for http://127.0.0.1:18200/v1/sys/health || fail "Vault did not start: $(tail -3 vault.log)"
  scenario vault "vault+http://127.0.0.1:18200/secret/capsule" "VAULT_TOKEN=capsuletest"
else
  echo "skip vault: could not download Vault"
fi

echo "all checks passed"
