#!/bin/sh

set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 ELF..." >&2
    exit 2
fi

for artifact do
    if ! program_headers=$(readelf -W -l "$artifact" 2>/dev/null); then
        echo "$artifact: could not read ELF program headers" >&2
        exit 1
    fi
    if ! dynamic_section=$(readelf -W -d "$artifact" 2>/dev/null); then
        echo "$artifact: could not read ELF dynamic section" >&2
        exit 1
    fi

    if ! printf '%s\n' "$program_headers" | grep -q 'GNU_RELRO'; then
        echo "$artifact: missing GNU_RELRO" >&2
        exit 1
    fi
    stack_flags=$(printf '%s\n' "$program_headers" |
        awk '/GNU_STACK/ { print $(NF - 1); found = 1 } END { if (!found) exit 1 }')
    if [ "$stack_flags" != "RW" ]; then
        echo "$artifact: executable or malformed GNU_STACK ($stack_flags)" >&2
        exit 1
    fi
    if ! printf '%s\n' "$dynamic_section" | grep -q 'BIND_NOW'; then
        echo "$artifact: missing immediate binding (Full RELRO)" >&2
        exit 1
    fi
    if printf '%s\n' "$dynamic_section" | grep -Eq 'RPATH|RUNPATH|TEXTREL'; then
        echo "$artifact: unsafe dynamic-linker metadata" >&2
        exit 1
    fi
done

echo "All ELF hardening checks passed."
