CC ?= cc
CXX ?= c++
CLANG ?= clang
BUILD_DIR ?= build
CXX_STDLIB_DIR := $(dir $(shell $(CXX) -print-file-name=libstdc++.so))

TEST_CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic \
	-fstack-protector-strong $(CFLAGS_EXTRA)
MODULE_CFLAGS := $(CFLAGS) -fPIC
LDFLAGS_EXTRA ?=

HARNESS := $(BUILD_DIR)/pam_harness
TEST_MODULE := $(BUILD_DIR)/pam_test_result.so
PARSER_TEST := $(BUILD_DIR)/test_partial_key_parser
PARSER_FUZZ := $(BUILD_DIR)/fuzz_partial_key_parser
CHRONO_TEST := $(BUILD_DIR)/test_chronoguard_helpers
SCHOOL_TEST := $(BUILD_DIR)/test_school_schedule_helpers
LIBOATH_TEST := $(BUILD_DIR)/test_liboath_window
HELPER_TESTS := $(CHRONO_TEST) $(SCHOOL_TEST) $(LIBOATH_TEST)
PRODUCTION_DIR := $(BUILD_DIR)/production
PRODUCTION_ARTIFACTS := \
	$(PRODUCTION_DIR)/pam_sandwich.so \
	$(PRODUCTION_DIR)/pam_strict_totp.so \
	$(PRODUCTION_DIR)/pam_chronoguard.so \
	$(PRODUCTION_DIR)/pam_partial_key.so \
	$(PRODUCTION_DIR)/pk_manager \
	$(PRODUCTION_DIR)/pam_school_schedule.so \
	$(PRODUCTION_DIR)/pam_2man_totp.so

.PHONY: all production test fuzz analyze analyze-production valgrind verify clean

all: $(HARNESS) $(TEST_MODULE)

$(BUILD_DIR):
	mkdir -p $@

$(HARNESS): pam_harness.c | $(BUILD_DIR)
	$(CC) $(TEST_CPPFLAGS) $(CFLAGS) $< -o $@ -lpam $(LDFLAGS_EXTRA)

$(TEST_MODULE): pam_test_result.c | $(BUILD_DIR)
	$(CC) $(TEST_CPPFLAGS) $(MODULE_CFLAGS) -shared $< -o $@ -lpam \
		$(LDFLAGS_EXTRA)

$(PARSER_TEST): test_partial_key_parser.c ../pam_partial_key/keyfile.c \
		../pam_partial_key/keyfile.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) test_partial_key_parser.c ../pam_partial_key/keyfile.c \
		-o $@ $(LDFLAGS_EXTRA)

$(CHRONO_TEST): test_chronoguard_helpers.c \
		../pam_chronoguard/pam_chronoguard.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -lpam $(LDFLAGS_EXTRA)

$(SCHOOL_TEST): test_school_schedule_helpers.c \
		../pam_school_schedule/pam_school_schedule.c | $(BUILD_DIR)
	$(CC) $(TEST_CPPFLAGS) $(CFLAGS) $< -o $@ -lpam $(LDFLAGS_EXTRA)

$(LIBOATH_TEST): test_liboath_window.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -loath $(LDFLAGS_EXTRA)

$(PRODUCTION_DIR):
	mkdir -p $@

$(PRODUCTION_DIR)/pam_sandwich.so: ../pam-sandwich/pam_sandwich.c | $(PRODUCTION_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $< -o $@ -lpam -loath -pthread \
		$(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pam_strict_totp.so: ../pam_strict_totp/pam_strict_totp.c | $(PRODUCTION_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $< -o $@ -lpam -loath -pthread \
		$(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pam_chronoguard.so: ../pam_chronoguard/pam_chronoguard.c | $(PRODUCTION_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $< -o $@ -lpam \
		$(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pam_partial_key.so: ../pam_partial_key/pam_partial_key.c \
		../pam_partial_key/keyfile.c ../pam_partial_key/keyfile.h | $(PRODUCTION_DIR)
	$(CC) $(MODULE_CFLAGS) -shared ../pam_partial_key/pam_partial_key.c \
		../pam_partial_key/keyfile.c -o $@ -lpam -lcrypto \
		$(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pk_manager: ../pam_partial_key/pk_manager.c | $(PRODUCTION_DIR)
	$(CC) $(CFLAGS) $< -o $@ -lcrypto $(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pam_school_schedule.so: ../pam_school_schedule/pam_school_schedule.c | $(PRODUCTION_DIR)
	$(CC) -D_GNU_SOURCE $(MODULE_CFLAGS) -shared $< -o $@ -lpam \
		$(LDFLAGS_EXTRA)

$(PRODUCTION_DIR)/pam_2man_totp.so: ../pam_2man_totp/pam_2man_totp.c | $(PRODUCTION_DIR)
	$(CC) $(MODULE_CFLAGS) -shared $< -o $@ -lpam -loath -pthread \
		$(LDFLAGS_EXTRA)

production: $(PRODUCTION_ARTIFACTS)

test: all $(PARSER_TEST) $(HELPER_TESTS)
	sh ./test_pam_stack.sh $(BUILD_DIR)
	$(PARSER_TEST)
	$(CHRONO_TEST)
	$(SCHOOL_TEST)
	$(LIBOATH_TEST)

fuzz: | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/fuzz-artifacts
	$(CLANG) -std=c11 -O1 -g -fno-omit-frame-pointer \
		-fsanitize=fuzzer,address,undefined fuzz_partial_key_parser.c \
		../pam_partial_key/keyfile.c -L$(CXX_STDLIB_DIR) -o $(PARSER_FUZZ)
	$(PARSER_FUZZ) -runs=10000 -max_len=4225 \
		-artifact_prefix=$(BUILD_DIR)/fuzz-artifacts/

analyze:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text $(TEST_CPPFLAGS) \
		-std=c11 -Wall -Wextra -Wpedantic pam_harness.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text $(TEST_CPPFLAGS) \
		-std=c11 -Wall -Wextra -Wpedantic pam_test_result.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic test_partial_key_parser.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic ../pam_partial_key/keyfile.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic test_chronoguard_helpers.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text $(TEST_CPPFLAGS) \
		-std=c11 -Wall -Wextra -Wpedantic test_school_schedule_helpers.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text \
		-std=c11 -Wall -Wextra -Wpedantic test_liboath_window.c

analyze-production:
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam-sandwich/pam_sandwich.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_strict_totp/pam_strict_totp.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_chronoguard/pam_chronoguard.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_partial_key/pam_partial_key.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_partial_key/keyfile.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_partial_key/pk_manager.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_school_schedule/pam_school_schedule.c
	$(CLANG) --analyze -Xanalyzer -analyzer-output=text ../pam_2man_totp/pam_2man_totp.c

valgrind: all $(PARSER_TEST) $(HELPER_TESTS)
	PAM_HARNESS_RUNNER='valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite --error-exitcode=99 --suppressions=valgrind.supp' \
		sh ./test_pam_stack.sh $(BUILD_DIR)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(PARSER_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(CHRONO_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(SCHOOL_TEST)
	valgrind --leak-check=full --show-leak-kinds=definite \
		--errors-for-leak-kinds=definite --error-exitcode=99 $(LIBOATH_TEST)

verify:
	$(MAKE) BUILD_DIR=build/gcc CC=gcc test production
	$(MAKE) BUILD_DIR=build/clang CC=clang test production
	$(MAKE) BUILD_DIR=build/fuzz fuzz
	$(MAKE) analyze
	$(MAKE) analyze-production
	$(MAKE) BUILD_DIR=build/gcc valgrind
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
	$(MAKE) BUILD_DIR=build/sanitize CC=clang \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test

clean:
	rm -rf -- build
