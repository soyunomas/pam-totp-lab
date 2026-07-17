CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
MODULE_CFLAGS := $(CFLAGS) -fPIC
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now
MODULE := $(BUILD_DIR)/pam_totp_slot_challenge.so
POLICY_TEST := $(BUILD_DIR)/test_slot_policy
SECRET_TEST := $(BUILD_DIR)/test_secret
CONFIG_TEST := $(BUILD_DIR)/test_config
MODULE_TEST := $(BUILD_DIR)/test_module
CONCURRENCY_TEST := $(BUILD_DIR)/test_concurrency
TESTS := $(POLICY_TEST) $(SECRET_TEST) $(CONFIG_TEST) $(MODULE_TEST) \
	$(CONCURRENCY_TEST)

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

$(POLICY_TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_slot_policy.c slot_policy.c -o $@

$(SECRET_TEST): tests/test_secret.c secret.c secret.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_secret.c secret.c slot_policy.c -o $@

$(CONFIG_TEST): tests/test_config.c config.c config.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_config.c config.c slot_policy.c -o $@

$(MODULE_TEST): tests/test_module.c pam_totp_slot_challenge.c config.c \
		config.h secret.h slot_policy.h tests/stubs/security/pam_modules.h \
		tests/stubs/security/pam_ext.h tests/stubs/liboath/oath.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Itests/stubs tests/test_module.c \
		pam_totp_slot_challenge.c config.c -o $@ -pthread

$(CONCURRENCY_TEST): tests/test_concurrency.c secret.c secret.h slot_policy.c \
		slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_concurrency.c secret.c slot_policy.c \
		-o $@ -pthread

$(MODULE): pam_totp_slot_challenge.c config.c config.h secret.c secret.h \
		slot_policy.c slot_policy.h ../pam_common/totp_replay.c \
		../pam_common/totp_replay.h | $(BUILD_DIR)
	$(CC) $(MODULE_CFLAGS) -shared pam_totp_slot_challenge.c config.c \
		secret.c slot_policy.c ../pam_common/totp_replay.c -o $@ \
		-lpam -loath -pthread $(HARDEN_LDFLAGS)

production: $(MODULE)

test: $(TESTS)
	$(POLICY_TEST)
	$(SECRET_TEST)
	$(CONFIG_TEST)
	$(MODULE_TEST)
	$(CONCURRENCY_TEST)

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic slot_policy.c \
		tests/test_slot_policy.c secret.c tests/test_secret.c config.c \
		tests/test_config.c tests/test_concurrency.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic -Itests/stubs \
		pam_totp_slot_challenge.c tests/test_module.c

syntax:
	$(CLANG) -fsyntax-only -std=c11 -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs pam_totp_slot_challenge.c config.c secret.c slot_policy.c

sanitize: | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_slot_policy.c slot_policy.c -o $(BUILD_DIR)/policy_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/policy_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_secret.c secret.c slot_policy.c -o $(BUILD_DIR)/secret_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/secret_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_config.c config.c slot_policy.c -o $(BUILD_DIR)/config_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/config_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs tests/test_module.c pam_totp_slot_challenge.c config.c \
		-o $(BUILD_DIR)/module_san -pthread
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/module_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_concurrency.c secret.c slot_policy.c \
		-o $(BUILD_DIR)/concurrency_san -pthread
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/concurrency_san

valgrind: $(TESTS)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(POLICY_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(SECRET_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(CONFIG_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(MODULE_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(CONCURRENCY_TEST)

hardening: production
	sh ../tests/test_elf_hardening.sh $(MODULE)

verify-local: clean test analyze syntax sanitize

verify:
	$(MAKE) BUILD_DIR=build/gcc CC=gcc clean test production hardening
	$(MAKE) BUILD_DIR=build/clang CC=clang clean test production hardening
	$(MAKE) analyze
	$(MAKE) BUILD_DIR=build/valgrind CC=gcc clean valgrind
	$(MAKE) BUILD_DIR=build/sanitize clean sanitize

install: production
	@if [ ! -d "$(PAM_DIR)" ]; then echo "PAM directory not found" >&2; exit 1; fi
	sudo install -o root -g root -m 0644 $(MODULE) $(PAM_DIR)/pam_totp_slot_challenge.so

uninstall:
	sudo rm -f -- $(PAM_DIR)/pam_totp_slot_challenge.so

clean:
	rm -rf -- $(BUILD_DIR)
