#!/bin/sh

set -eu
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BUILD_DIR" >&2
    exit 2
fi

build_dir=$(realpath "$1")
harness="$build_dir/pam_harness"
module="$build_dir/pam_test_result.so"
test_root=$(mktemp -d)
conf_dir="$test_root/pam.d"
mkdir -p "$conf_dir"

cleanup() {
    rm -rf -- "$test_root"
}
trap cleanup EXIT HUP INT TERM

write_service() {
    service=$1
    shift
    printf '%s\n' "$@" > "$conf_dir/$service"
}

run_case() {
    name=$1
    expected=$2
    shift 2
    echo "CASE $name"
    if [ -n "${PAM_HARNESS_RUNNER:-}" ]; then
        # PAM_HARNESS_RUNNER intentionally expands to a command and options.
        # It is set only by the local Makefile for tools such as Valgrind.
        # shellcheck disable=SC2086
        $PAM_HARNESS_RUNNER "$harness" "$conf_dir" "$name" nobody \
            "$expected" "$@"
    else
        "$harness" "$conf_dir" "$name" nobody "$expected" "$@"
    fi
}

write_service required_success \
    "auth required $module result=success"
run_case required_success success

write_service ignore_then_success \
    "auth required $module result=ignore" \
    "auth required $module result=success"
run_case ignore_then_success success

write_service ignore_only \
    "auth required $module result=ignore"
run_case ignore_only perm_denied

write_service failure_then_success \
    "auth required $module result=auth_err" \
    "auth required $module result=success"
run_case failure_then_success auth_err

write_service prompt_success \
    "auth required $module result=success expect=swordfish"
run_case prompt_success success swordfish

write_service prompt_failure \
    "auth required $module result=success expect=swordfish"
run_case prompt_failure auth_err incorrect

write_service missing_response \
    "auth required $module result=success expect=swordfish"
run_case missing_response conv_err

echo "All isolated PAM stack tests passed."
