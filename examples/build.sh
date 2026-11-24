#!/bin/sh
# Build and seal one of the examples:   sh examples/build.sh <example> <private key>
#   sh examples/build.sh python-web dev.key
# The capsule is written to examples/out/<its name>. Needs curl for the first build.
set -eu
HERE=$(dirname "$(realpath "$0")")
[ $# = 2 ] && [ -f "$HERE/$1/capsule.cue" ] && [ -f "$2" ] || { echo "usage: sh examples/build.sh <python-web|python-job|java-web> <private key>"; exit 1; }
case $1 in
  python-*) sh "$HERE/fetch.sh" alpine python ;;
  java-*) sh "$HERE/fetch.sh" alpine java ;;
esac
name=$(grep -m1 'name:' "$HERE/$1/capsule.cue" | cut -d'"' -f2)
mkdir -p "$HERE/out"
capsule build -force -key "$2" -o "$HERE/out/$name" "$HERE/$1/capsule.cue"
