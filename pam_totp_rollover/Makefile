CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
MODULE_CFLAGS := $(CFLAGS) -fPIC
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now

MODULE := $(BUILD_DIR)/pam_totp_rollover.so
CORE_TEST := $(BUILD_DIR)/test_rollover
SCOPE_TEST := $(BUILD_DIR)/test_scope
SECRET_TEST := $(BUILD_DIR)/test_secret
STATE_TEST := $(BUILD_DIR)/test_state
MODULE_TEST := $(BUILD_DIR)/test_module
TESTS := $(CORE_TEST) $(SCOPE_TEST) $(SECRET_TEST) $(STATE_TEST) $(MODULE_TEST)

MODULE_SOURCES := pam_totp_rollover.c rollover.c rollover_clock.c scope.c \
	../pam_common/user_totp_secret.c ../pam_common/totp_replay.c

ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
PAM_DIR := /usr/lib64/security
else
PAM_DIR := /lib/security
endif

.PHONY: all production test analyze syntax sanitize valgrind hardening \
	verify-local verify install uninstall clean

all: production

$(BUILD_DIR):
	mkdir -p $@

$(CORE_TEST): tests/test_rollover.c rollover.c rollover.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_rollover.c rollover.c -o $@

$(SCOPE_TEST): tests/test_scope.c scope.c scope.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_scope.c scope.c -o $@ -lcrypto

$(SECRET_TEST): tests/test_secret.c ../pam_common/user_totp_secret.c \
		../pam_common/user_totp_secret.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_secret.c ../pam_common/user_totp_secret.c -o $@

$(STATE_TEST): ../tests/test_totp_replay.c ../pam_common/totp_replay.c \
		../pam_common/totp_replay.h | $(BUILD_DIR)
	$(CC) -DTOTP_REPLAY_TESTING $(CFLAGS) ../tests/test_totp_replay.c \
		../pam_common/totp_replay.c -o $@

$(MODULE_TEST): tests/test_module.c pam_totp_rollover.c rollover.c rollover.h \
		rollover_clock.h scope.c scope.h ../pam_common/user_totp_secret.h \
		../pam_common/totp_replay.h tests/stubs/security/pam_modules.h \
		tests/stubs/security/pam_ext.h tests/stubs/liboath/oath.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Itests/stubs tests/test_module.c \
		pam_totp_rollover.c rollover.c scope.c -o $@ -lcrypto -pthread

$(MODULE): $(MODULE_SOURCES) rollover.h rollover_clock.h scope.h \
		../pam_common/user_totp_secret.h ../pam_common/totp_replay.h | $(BUILD_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $(MODULE_SOURCES) -o $@ \
		-lpam -loath -lcrypto -pthread $(HARDEN_LDFLAGS)

production: $(MODULE)

test: $(TESTS)
	$(CORE_TEST)
	$(SCOPE_TEST)
	$(SECRET_TEST)
	$(STATE_TEST)
	$(MODULE_TEST)

syntax:
	$(CLANG) -fsyntax-only -std=c11 -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs pam_totp_rollover.c rollover.c scope.c
	$(CLANG) -fsyntax-only -std=c11 -Wall -Wextra -Werror -Wpedantic \
		rollover_clock.c ../pam_common/user_totp_secret.c \
		../pam_common/totp_replay.c

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic rollover.c rollover_clock.c scope.c \
		../pam_common/user_totp_secret.c ../pam_common/totp_replay.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic -Itests/stubs \
		pam_totp_rollover.c tests/test_module.c

sanitize: | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_rollover.c rollover.c -o $(BUILD_DIR)/core_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/core_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_scope.c scope.c -o $(BUILD_DIR)/scope_san -lcrypto
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/scope_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_secret.c ../pam_common/user_totp_secret.c \
		-o $(BUILD_DIR)/secret_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/secret_san
	$(CLANG) -DTOTP_REPLAY_TESTING -std=c11 -O1 -g \
		-fno-omit-frame-pointer -fsanitize=address,undefined \
		-Wall -Wextra -Werror -Wpedantic ../tests/test_totp_replay.c \
		../pam_common/totp_replay.c -o $(BUILD_DIR)/state_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/state_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs tests/test_module.c pam_totp_rollover.c rollover.c \
		scope.c -o $(BUILD_DIR)/module_san -lcrypto -pthread
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/module_san

valgrind: $(TESTS)
	for test_binary in $(TESTS); do \
		valgrind --leak-check=full --show-leak-kinds=definite \
			--errors-for-leak-kinds=definite --error-exitcode=99 \
			$$test_binary || exit $$?; \
	done

hardening: production
	sh ../tests/test_elf_hardening.sh $(MODULE)

verify-local: clean test syntax analyze sanitize

verify:
	$(MAKE) BUILD_DIR=build/gcc CC=gcc clean test production hardening
	$(MAKE) BUILD_DIR=build/clang CC=clang clean test production hardening
	$(MAKE) analyze
	$(MAKE) BUILD_DIR=build/valgrind CC=gcc clean valgrind
	$(MAKE) BUILD_DIR=build/sanitize clean sanitize

install: production
	install -o root -g root -m 0644 $(MODULE) \
		$(PAM_DIR)/pam_totp_rollover.so

uninstall:
	rm -f -- $(PAM_DIR)/pam_totp_rollover.so

clean:
	rm -rf -- $(BUILD_DIR)
	rm -f -- *.plist tests/*.plist ../pam_common/*.plist
