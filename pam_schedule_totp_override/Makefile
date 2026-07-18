CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
MODULE_CFLAGS := $(CFLAGS) -fPIC
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now
MODULE := $(BUILD_DIR)/pam_schedule_totp_override.so
SCHEDULE_TEST := $(BUILD_DIR)/test_schedule
STORE_TEST := $(BUILD_DIR)/test_secure_store
RATE_TEST := $(BUILD_DIR)/test_rate_limit
MODULE_TEST := $(BUILD_DIR)/test_module
TESTS := $(SCHEDULE_TEST) $(STORE_TEST) $(RATE_TEST) $(MODULE_TEST)

ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
PAM_DIR := /usr/lib64/security
else
PAM_DIR := /lib/security
endif

.PHONY: all production test analyze syntax sanitize valgrind hardening \
	verify-local verify install uninstall clean deps

all: production

$(BUILD_DIR):
	mkdir -p $@

$(SCHEDULE_TEST): tests/test_schedule.c schedule.c schedule.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. tests/test_schedule.c schedule.c -o $@

$(STORE_TEST): tests/test_secure_store.c secure_store.c secure_store.h \
		schedule.c schedule.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. tests/test_secure_store.c secure_store.c schedule.c -o $@

$(RATE_TEST): tests/test_rate_limit.c rate_limit.c rate_limit.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. tests/test_rate_limit.c rate_limit.c -o $@ -pthread

$(MODULE_TEST): tests/test_module.c pam_schedule_totp_override.c schedule.h \
		secure_store.h rate_limit.h tests/stubs/security/pam_modules.h \
		tests/stubs/security/pam_ext.h tests/stubs/liboath/oath.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Itests/stubs -I. tests/test_module.c \
		pam_schedule_totp_override.c -o $@ -pthread

$(MODULE): pam_schedule_totp_override.c schedule.c schedule.h secure_store.c \
		secure_store.h rate_limit.c rate_limit.h ../pam_common/totp_replay.c \
		../pam_common/totp_replay.h | $(BUILD_DIR)
	$(CC) $(MODULE_CFLAGS) -shared pam_schedule_totp_override.c schedule.c \
		secure_store.c rate_limit.c ../pam_common/totp_replay.c -o $@ \
		-lpam -loath -pthread $(HARDEN_LDFLAGS)

production: $(MODULE)

test: $(TESTS)
	$(SCHEDULE_TEST)
	$(STORE_TEST)
	$(RATE_TEST)
	$(MODULE_TEST)

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic schedule.c tests/test_schedule.c \
		secure_store.c tests/test_secure_store.c rate_limit.c \
		tests/test_rate_limit.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic -Itests/stubs -I. \
		pam_schedule_totp_override.c tests/test_module.c

syntax:
	$(CLANG) -fsyntax-only -std=c11 -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs -I. pam_schedule_totp_override.c schedule.c \
		secure_store.c rate_limit.c

sanitize: | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-I. tests/test_schedule.c schedule.c -o $(BUILD_DIR)/schedule_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/schedule_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-I. tests/test_secure_store.c secure_store.c schedule.c \
		-o $(BUILD_DIR)/store_san
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/store_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-I. tests/test_rate_limit.c rate_limit.c -o $(BUILD_DIR)/rate_san -pthread
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/rate_san
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs -I. tests/test_module.c pam_schedule_totp_override.c \
		-o $(BUILD_DIR)/module_san -pthread
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/module_san

valgrind: $(TESTS)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(SCHEDULE_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(STORE_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(RATE_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(MODULE_TEST)

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
	sudo install -o root -g root -m 0644 $(MODULE) \
		$(PAM_DIR)/pam_schedule_totp_override.so

uninstall:
	sudo rm -f -- $(PAM_DIR)/pam_schedule_totp_override.so

deps:
	sudo apt-get update
	sudo apt-get install -y build-essential clang libpam0g-dev liboath-dev \
		valgrind binutils

clean:
	rm -rf -- $(BUILD_DIR)
	rm -f -- *.plist tests/*.plist
