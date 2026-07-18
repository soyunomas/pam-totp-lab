CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong
MODULE_CFLAGS := $(CFLAGS) -fPIC
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now
MODULE := $(BUILD_DIR)/pam_schedule_partial_key_override.so
MANAGER := $(BUILD_DIR)/schedule_partial_key_manager
CORE_TEST := $(BUILD_DIR)/test_core
MODULE_TEST := $(BUILD_DIR)/test_module
MANAGER_TEST := $(BUILD_DIR)/test_manager
COMMON := ../pam_schedule_totp_override/schedule.c \
	../pam_schedule_totp_override/rate_limit.c ../pam_partial_key/keyfile.c

ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
PAM_DIR := /lib/x86_64-linux-gnu/security
else
PAM_DIR := /lib/security
endif

.PHONY: all test hardening verify install uninstall clean

all: $(MODULE) $(MANAGER)

$(BUILD_DIR):
	mkdir -p $@

$(MODULE): pam_schedule_partial_key_override.c secure_store.c challenge.c \
		$(COMMON) | $(BUILD_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $^ -o $@ -lpam -lcrypto -pthread \
		$(HARDEN_LDFLAGS)

$(MANAGER): schedule_partial_key_manager.c ../pam_partial_key/keyfile.c \
		../pam_schedule_totp_override/schedule.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto $(HARDEN_LDFLAGS)

$(MANAGER_TEST): schedule_partial_key_manager.c ../pam_partial_key/keyfile.c \
		../pam_schedule_totp_override/schedule.c | $(BUILD_DIR)
	$(CC) -DSPK_MANAGER_TESTING $(CFLAGS) $^ -o $@ -lcrypto

$(CORE_TEST): tests/test_core.c challenge.c \
		../pam_schedule_totp_override/schedule.c \
		../pam_schedule_totp_override/rate_limit.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. $^ -o $@ -lcrypto -pthread

$(MODULE_TEST): tests/test_module.c pam_schedule_partial_key_override.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I../pam_schedule_totp_override/tests/stubs -I. $^ \
		-o $@ -lcrypto

test: $(CORE_TEST) $(MODULE_TEST) $(MANAGER_TEST)
	$(CORE_TEST)
	$(MODULE_TEST)
	sh tests/test_manager.sh $(MANAGER_TEST)

hardening: all
	sh ../tests/test_elf_hardening.sh $(MODULE) $(MANAGER)

verify: clean test all hardening
	$(CLANG) --analyze -std=c11 -Wall -Wextra -Wpedantic \
		pam_schedule_partial_key_override.c secure_store.c challenge.c \
		schedule_partial_key_manager.c

install: all
	install -o root -g root -m 0644 $(MODULE) \
		$(PAM_DIR)/pam_schedule_partial_key_override.so
	install -o root -g root -m 0755 $(MANAGER) \
		/usr/local/bin/schedule_partial_key_manager
	install -d -o root -g root -m 0700 \
		/etc/security/pam-schedule-partial-key
	install -d -o root -g root -m 0700 \
		/var/lib/pam-schedule-partial-key

uninstall:
	rm -f $(PAM_DIR)/pam_schedule_partial_key_override.so
	rm -f /usr/local/bin/schedule_partial_key_manager

clean:
	rm -rf -- $(BUILD_DIR)
	rm -f -- *.plist tests/*.plist
