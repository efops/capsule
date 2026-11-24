#!/bin/sh
# Download what the examples are built from, for this machine's architecture,
# into examples/.cache:   sh examples/fetch.sh [alpine] [python] [java]
#   alpine  a 3 MB Alpine Linux root filesystem (the base of every example)
#   python  a self-contained CPython 3.12 (about 25 MB)
#   java    the Eclipse Temurin 21 JDK for Alpine (about 200 MB)
# Files already there are kept. Needs curl.
set -eu
CACHE=$(dirname "$(realpath "$0")")/.cache
mkdir -p "$CACHE"
case $(uname -m) in
  aarch64 | arm64) ARCH=aarch64; JAVA_ARCH=aarch64 ;;
  *) ARCH=x86_64; JAVA_ARCH=x64 ;;
esac
get() { # $1 = file name in the cache, $2 = URL
  [ -s "$CACHE/$1" ] && return 0
  echo "downloading $1"
  curl -fsSL --retry 3 -o "$CACHE/$1.part" "$2" && mv "$CACHE/$1.part" "$CACHE/$1"
}
for what in "${@:-alpine}"; do
  case $what in
    alpine)
      get alpine.tar.gz "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/$ARCH/alpine-minirootfs-3.20.3-$ARCH.tar.gz" ;;
    python)
      # The newest CPython 3.12 built against musl, which is what Alpine uses.
      url=$(curl -fsSL https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest |
        grep -o "https://[^\"]*cpython-3\.12[^\"]*-$ARCH-unknown-linux-musl-install_only\.tar\.gz" | head -1)
      [ -n "$url" ] || { echo "could not find a Python build for $ARCH"; exit 1; }
      get python.tar.gz "$url" ;;
    java)
      get jdk.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/alpine-linux/$JAVA_ARCH/jdk/hotspot/normal/eclipse" ;;
    *) echo "unknown: $what (want alpine, python or java)"; exit 1 ;;
  esac
done
