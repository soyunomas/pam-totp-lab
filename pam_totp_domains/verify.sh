#!/bin/sh

set -eu
umask 077

mode=${1:-verify}
build_dir=build
mkdir -p "$build_dir"

common_flags='-std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong'

build_tests() {
    cc -DTOTP_REPLAY_TESTING $common_flags \
        test_domains.c domains.c secret_file.c ../pam_common/totp_replay.c \
        -o "$build_dir/test_domains"
}

run_tests() {
    "$build_dir/test_domains"
}

build_module() {
    cc $common_flags -fPIC -shared pam_totp_domains.c domains.c secret_file.c \
        ../pam_common/totp_replay.c -o "$build_dir/pam_totp_domains.so" \
        -lpam -loath -pthread -Wl,-z,relro,-z,now
}

check_elf() {
    headers=$(readelf -W -l "$build_dir/pam_totp_domains.so")
    dynamic=$(readelf -W -d "$build_dir/pam_totp_domains.so")
    printf '%s\n' "$headers" | grep -q GNU_RELRO
    [ "$(printf '%s\n' "$headers" | awk '/GNU_STACK/ {print $(NF-1)}')" = RW ]
    printf '%s\n' "$dynamic" | grep -q BIND_NOW
    ! printf '%s\n' "$dynamic" | grep -Eq 'RPATH|RUNPATH|TEXTREL'
}

analyze() {
    clang --analyze -Xanalyzer -analyzer-output=text \
        -DTOTP_REPLAY_TESTING -std=c11 -Wall -Wextra -Wpedantic \
        test_domains.c domains.c secret_file.c ../pam_common/totp_replay.c
    clang --analyze -Xanalyzer -analyzer-output=text \
        pam_totp_domains.c domains.c secret_file.c ../pam_common/totp_replay.c
}

build_tests
run_tests
[ "$mode" = test ] && exit 0

build_module
check_elf
analyze

valgrind --leak-check=full --show-leak-kinds=definite \
    --errors-for-leak-kinds=definite --error-exitcode=99 \
    "$build_dir/test_domains"

clang -DTOTP_REPLAY_TESTING -std=c11 -O1 -g -fno-omit-frame-pointer \
    -Wall -Wextra -Werror -Wpedantic -fsanitize=address,undefined \
    test_domains.c domains.c secret_file.c ../pam_common/totp_replay.c \
    -o "$build_dir/test_domains_sanitize"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 "$build_dir/test_domains_sanitize"

echo "pam_totp_domains verification passed"
