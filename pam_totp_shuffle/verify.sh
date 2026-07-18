#!/bin/sh
set -eu

make clean
make BUILD_DIR=build/gcc CC=gcc test build hardening
make BUILD_DIR=build/clang CC=clang test build hardening
make analyze
make BUILD_DIR=build/gcc valgrind
make BUILD_DIR=build/sanitize sanitize
