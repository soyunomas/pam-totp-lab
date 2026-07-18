CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build

CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong $(CFLAGS_EXTRA)
MODULE_CFLAGS := $(CFLAGS) -fPIC
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now
LDFLAGS_EXTRA ?=

MODULE := $(BUILD_DIR)/pam_totp_shuffle.so
SHUFFLE_TEST := $(BUILD_DIR)/test_shuffle
SECRET_TEST := $(BUILD_DIR)/test_secret
MODULE_SOURCES := pam_totp_shuffle.c shuffle.c secret.c ../pam_common/totp_replay.c

ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
PAM_DIR := /usr/lib64/security
else
PAM_DIR := /lib/security
endif

.PHONY: all build test hardening analyze valgrind sanitize verify install uninstall clean

all: build

$(BUILD_DIR)/.dir:
	mkdir -p $(BUILD_DIR)
	touch $@

$(MODULE): $(MODULE_SOURCES) shuffle.h secret.h ../pam_common/totp_replay.h | $(BUILD_DIR)/.dir
	$(CC) $(MODULE_CFLAGS) -shared $(MODULE_SOURCES) -o $@ \
		-lpam -loath -pthread $(HARDEN_LDFLAGS) $(LDFLAGS_EXTRA)

$(SHUFFLE_TEST): tests/test_shuffle.c shuffle.c shuffle.h | $(BUILD_DIR)/.dir
	$(CC) $(CFLAGS) -I. tests/test_shuffle.c shuffle.c -o $@ $(LDFLAGS_EXTRA)

$(SECRET_TEST): tests/test_secret.c secret.c secret.h | $(BUILD_DIR)/.dir
	$(CC) $(CFLAGS) -I. tests/test_secret.c secret.c -o $@ $(LDFLAGS_EXTRA)

build: $(MODULE)

test: $(SHUFFLE_TEST) $(SECRET_TEST)
	$(SHUFFLE_TEST)
	$(SECRET_TEST)

hardening: build
	sh ../tests/test_elf_hardening.sh $(MODULE)

analyze:
	$(CLANG) --analyze -std=c11 -Wall -Wextra -Wpedantic shuffle.c
	$(CLANG) --analyze -std=c11 -Wall -Wextra -Wpedantic secret.c
	$(CLANG) --analyze -std=c11 -Wall -Wextra -Wpedantic pam_totp_shuffle.c

valgrind: test
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(SHUFFLE_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(SECRET_TEST)

sanitize:
	mkdir -p $(BUILD_DIR)/sanitize
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic -I. \
		tests/test_shuffle.c shuffle.c -o $(BUILD_DIR)/sanitize/test_shuffle
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined -Wall -Wextra -Werror -Wpedantic -I. \
		tests/test_secret.c secret.c -o $(BUILD_DIR)/sanitize/test_secret
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
		$(BUILD_DIR)/sanitize/test_shuffle
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
		$(BUILD_DIR)/sanitize/test_secret

verify:
	sh ./verify.sh

install: build
	@test -d "$(PAM_DIR)" || { echo "Directorio PAM no encontrado: $(PAM_DIR)"; exit 1; }
	install -o root -g root -m 0644 $(MODULE) $(PAM_DIR)/pam_totp_shuffle.so

uninstall:
	rm -f $(PAM_DIR)/pam_totp_shuffle.so

clean:
	rm -rf -- build
