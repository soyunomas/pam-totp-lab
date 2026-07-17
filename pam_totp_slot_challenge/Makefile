CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
POLICY_TEST := $(BUILD_DIR)/test_slot_policy
SECRET_TEST := $(BUILD_DIR)/test_secret
CONFIG_TEST := $(BUILD_DIR)/test_config
TESTS := $(POLICY_TEST) $(SECRET_TEST) $(CONFIG_TEST)

.PHONY: all test analyze sanitize syntax verify clean

all: test

$(BUILD_DIR):
	mkdir -p $@

$(POLICY_TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_slot_policy.c slot_policy.c -o $@

$(SECRET_TEST): tests/test_secret.c secret.c secret.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_secret.c secret.c slot_policy.c -o $@

$(CONFIG_TEST): tests/test_config.c config.c config.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_config.c config.c slot_policy.c -o $@

test: $(TESTS)
	$(POLICY_TEST)
	$(SECRET_TEST)
	$(CONFIG_TEST)

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic \
		slot_policy.c tests/test_slot_policy.c secret.c tests/test_secret.c \
		config.c tests/test_config.c

syntax:
	$(CLANG) -fsyntax-only -std=c11 -Wall -Wextra -Werror -Wpedantic \
		-Itests/stubs pam_totp_slot_challenge.c config.c secret.c slot_policy.c

sanitize: | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address \
		-Wall -Wextra -Werror -Wpedantic tests/test_slot_policy.c slot_policy.c \
		-o $(BUILD_DIR)/policy_asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(BUILD_DIR)/policy_asan
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address \
		-Wall -Wextra -Werror -Wpedantic tests/test_secret.c secret.c slot_policy.c \
		-o $(BUILD_DIR)/secret_asan
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(BUILD_DIR)/secret_asan
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=undefined \
		-Wall -Wextra -Werror -Wpedantic tests/test_config.c config.c slot_policy.c \
		-o $(BUILD_DIR)/config_ubsan
	UBSAN_OPTIONS=halt_on_error=1 $(BUILD_DIR)/config_ubsan

verify: clean test analyze syntax sanitize

clean:
	rm -rf -- $(BUILD_DIR)
