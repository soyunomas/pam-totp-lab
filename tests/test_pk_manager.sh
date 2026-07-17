#!/bin/sh

set -eu
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: $0 PK_MANAGER" >&2
    exit 2
fi

manager=$(realpath "$1")
test_root=$(mktemp -d)

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

run_manager() {
    password=$1
    home_dir=$2
    if [ -n "${PK_MANAGER_RUNNER:-}" ]; then
        # The runner is supplied only by the test Makefile (for Valgrind).
        # shellcheck disable=SC2086
        printf '%s\n' "$password" | env HOME="$home_dir" \
            $PK_MANAGER_RUNNER "$manager" >/dev/null 2>&1
    else
        printf '%s\n' "$password" | env HOME="$home_dir" \
            "$manager" >/dev/null 2>&1
    fi
}

run_manager_capture_error() {
    password=$1
    home_dir=$2
    error_file=$3
    printf '%s\n' "$password" | env HOME="$home_dir" \
        PK_MANAGER_TEST_FAIL_DIR_FSYNC=1 "$manager" > /dev/null \
        2> "$error_file"
}

home_valid="$test_root/valid"
mkdir "$home_valid"
run_manager "abcdefgh" "$home_valid"

key_file="$home_valid/.partial_key"
[ -f "$key_file" ]
[ ! -L "$key_file" ]
[ "$(stat -c '%a' "$key_file")" = "600" ]
[ "$(cut -d '|' -f 1 "$key_file")" = "8" ]
[ "$(awk -F '|' '{ print NF }' "$key_file")" = "10" ]
if grep -F "abcdefgh" "$key_file" >/dev/null; then
    echo "plaintext password found in generated key file" >&2
    exit 1
fi

home_long="$test_root/long"
mkdir "$home_long"
overlong=$(printf 'a%.0s' $(seq 1 65))
if run_manager "$overlong" "$home_long"; then
    echo "overlong password was accepted" >&2
    exit 1
fi
[ ! -e "$home_long/.partial_key" ]

home_symlink="$test_root/symlink"
mkdir "$home_symlink"
printf '%s\n' "do-not-overwrite" > "$test_root/victim"
ln -s "$test_root/victim" "$home_symlink/.partial_key"
run_manager "abcdefgh" "$home_symlink"
[ "$(cat "$test_root/victim")" = "do-not-overwrite" ]
[ -f "$home_symlink/.partial_key" ]
[ ! -L "$home_symlink/.partial_key" ]
[ "$(stat -c '%a' "$home_symlink/.partial_key")" = "600" ]

home_uncertain="$test_root/uncertain"
mkdir "$home_uncertain"
printf '%s\n' "previous-key" > "$home_uncertain/.partial_key"
error_uncertain="$test_root/uncertain.err"
if run_manager_capture_error "abcdefgh" "$home_uncertain" \
        "$error_uncertain"; then
    echo "directory fsync failure was reported as success" >&2
    exit 1
fi
if grep -F "previous-key" "$home_uncertain/.partial_key" >/dev/null; then
    echo "directory fsync test did not cross the rename boundary" >&2
    exit 1
fi
grep -F "was replaced" "$error_uncertain" >/dev/null
grep -F "do not assume the previous key remains" "$error_uncertain" \
    >/dev/null

echo "All partial-key manager tests passed."
