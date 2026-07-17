CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
POLICY_TEST := $(BUILD_DIR)/test_slot_policy
SECRET_TEST := $(BUILD_DIR)/test_secret
POLICY_ASAN := $(BUILD_DIR)/test_slot_policy_asan
SECRET_ASAN := $(BUILD_DIR)/test_secret_asan
POLICY_UBSAN := $(BUILD_DIR)/test_slot_policy_ubsan
SECRET_UBSAN := $(BUILD_DIR)/test_secret_ubsan

.PHONY: all test analyze sanitize verify clean

all: test

$(BUILD_DIR):
	mkdir -p $@

$(POLICY_TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_slot_policy.c slot_policy.c -o $@

$(SECRET_TEST): tests/test_secret.c secret.c secret.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_secret.c secret.c slot_policy.c -o $@

$(POLICY_ASAN): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address -Wall -Wextra -Werror -Wpedantic \
		tests/test_slot_policy.c slot_policy.c -o $@

$(SECRET_ASAN): tests/test_secret.c secret.c secret.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address -Wall -Wextra -Werror -Wpedantic \
		tests/test_secret.c secret.c slot_policy.c -o $@

$(POLICY_UBSAN): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_slot_policy.c slot_policy.c -o $@

$(SECRET_UBSAN): tests/test_secret.c secret.c secret.h slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_secret.c secret.c slot_policy.c -o $@

test: $(POLICY_TEST) $(SECRET_TEST)
	$(POLICY_TEST)
	$(SECRET_TEST)

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic \
		slot_policy.c tests/test_slot_policy.c secret.c tests/test_secret.c

sanitize: $(POLICY_ASAN) $(SECRET_ASAN) $(POLICY_UBSAN) $(SECRET_UBSAN)
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(POLICY_ASAN)
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(SECRET_ASAN)
	UBSAN_OPTIONS=halt_on_error=1 $(POLICY_UBSAN)
	UBSAN_OPTIONS=halt_on_error=1 $(SECRET_UBSAN)

verify: clean test analyze sanitize

clean:
	rm -rf -- $(BUILD_DIR)
