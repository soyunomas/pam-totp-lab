#!/bin/sh

set -eu
umask 077

manager=$1
root=$(mktemp -d)
cleanup() { rm -rf -- "$root"; }
trap cleanup EXIT HUP INT TERM

printf '%s\n' 'Docente-Larga-2026' | \
    SPK_MANAGER_TEST_DIRECTORY="$root" "$manager" profesor-1 >/dev/null

key="$root/profesor-1.pkey"
[ -f "$key" ]
[ ! -L "$key" ]
[ "$(stat -c '%a' "$key")" = 600 ]
[ "$(cut -d '|' -f 1 "$key")" = 18 ]
[ "$(awk -F '|' '{print NF}' "$key")" = 20 ]
if grep -F 'Docente-Larga-2026' "$key" >/dev/null; then
    echo 'plaintext teacher key found in key file' >&2
    exit 1
fi
if printf '%s\n' 'abcdefgh' | \
    SPK_MANAGER_TEST_DIRECTORY="$root" "$manager" '../bad' >/dev/null 2>&1; then
    echo 'unsafe authorizer was accepted' >&2
    exit 1
fi

echo 'schedule partial-key manager tests passed'
