CC ?= cc
CLANG ?= clang
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong
TEST := $(BUILD_DIR)/test_slot_policy
ASAN_TEST := $(BUILD_DIR)/test_slot_policy_asan
UBSAN_TEST := $(BUILD_DIR)/test_slot_policy_ubsan

.PHONY: all test analyze sanitize verify clean

all: test

$(BUILD_DIR):
	mkdir -p $@

$(TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/test_slot_policy.c slot_policy.c -o $@

$(ASAN_TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=address -Wall -Wextra -Werror -Wpedantic \
		tests/test_slot_policy.c slot_policy.c -o $@

$(UBSAN_TEST): tests/test_slot_policy.c slot_policy.c slot_policy.h | $(BUILD_DIR)
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=undefined -Wall -Wextra -Werror -Wpedantic \
		tests/test_slot_policy.c slot_policy.c -o $@

test: $(TEST)
	$(TEST)

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic \
		slot_policy.c tests/test_slot_policy.c

sanitize: $(ASAN_TEST) $(UBSAN_TEST)
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 $(ASAN_TEST)
	UBSAN_OPTIONS=halt_on_error=1 $(UBSAN_TEST)

verify: clean test analyze sanitize

clean:
	rm -rf -- $(BUILD_DIR)
