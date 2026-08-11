#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 PAM_MODULE" >&2
    exit 2
fi

exports=$(nm -D --defined-only "$1" | awk '$2 ~ /^[TW]$/ { print $3 }' | sort)
expected=$(printf '%s\n' pam_sm_authenticate pam_sm_setcred)

if [ "$exports" != "$expected" ]; then
    echo "$1: unexpected exported symbols" >&2
    printf '%s\n' "$exports" >&2
    exit 1
fi

echo "PAM export check passed."
