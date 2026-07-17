# Isolated PAM test harness

These tests use Linux-PAM's `pam_start_confdir()` API to load service policies
from a temporary directory. They do not read or modify `/etc/pam.d`, install
modules, restart services, or authenticate real accounts.

The fixture module provides deterministic `PAM_SUCCESS`, `PAM_IGNORE`, and
error returns. This establishes the stack semantics needed before changing the
authentication modules.

Run the baseline tests with:

```sh
make -C tests test
make -C tests analyze
make -C tests valgrind
make -C tests hardening
```

The phase-one parser tests exercise valid boundary sizes, malformed fields,
embedded NUL bytes, missing and extra fields, and oversized key files. The
libFuzzer target adds AddressSanitizer and UndefinedBehaviorSanitizer coverage:

```sh
make -C tests fuzz
```

The deterministic liboath test fixes the expected window semantics: with a
window of one, the current counter returns position zero and the immediately
previous or next counter returns a positive successful position.

Build all current production artifacts into the ignored test directory instead
of overwriting the binaries tracked by the repository:

```sh
make -C tests production
```

Run the same tests with Clang in a separate build directory:

```sh
make -C tests BUILD_DIR=build/clang CC=clang test
```

Run the harness and fixture under AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
make -C tests \
  BUILD_DIR=build/sanitize \
  CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
  LDFLAGS_EXTRA='-fsanitize=address,undefined' \
  test
```

Production PAM modules are compiled but are intentionally not loaded by the
isolated harness. Their real file, user, time, and privilege dependencies need
dedicated test seams before executing them safely.

The complete verification gate is:

```sh
make -C tests verify
```

The matrix also tests `pk_manager`'s atomic installation, including mode `0600`,
overlong-password rejection, replacement of a symlink without modifying its
target, and the explicit result returned when `rename()` succeeds but directory
durability cannot be confirmed.

It runs the isolated stack and parser tests with GCC and Clang, builds every
production artifact away from the source directories, fuzzes the partial-key
parser, runs Clang Static Analyzer, checks the harness and parser with Valgrind,
executes the tests under AddressSanitizer and UndefinedBehaviorSanitizer, and
verifies Full RELRO, immediate binding, a non-executable stack, and the absence
of RPATH, RUNPATH, and TEXTREL metadata on every production ELF. There are no
warning exceptions in either production build.

Some restricted sandboxes deny `dlopen()` of the fixture module. In that case
the isolated stack tests must run outside that sandbox; they still use only a
private temporary policy directory and never fall back to `/etc/pam.d`.

On the Ubuntu 22.04 Linux-PAM 1.4 build used for the baseline,
`pam_start_confdir()` leaves one allocation whose size is exactly the temporary
configuration path plus its terminating byte. Both LeakSanitizer and Valgrind
attribute it to two internal `libpam` frames reached directly from
`pam_start_confdir()`. Valgrind applies the narrow stack suppression in
`valgrind.supp` and still fails on every other definite leak. LeakSanitizer's
leak pass is disabled for this harness, while AddressSanitizer and
UndefinedBehaviorSanitizer remain fatal for memory and undefined-behavior
errors.
