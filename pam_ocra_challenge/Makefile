CC ?= cc

BUILD_DIR ?= build/$(notdir $(CC))
CPPFLAGS ?=
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic
CFLAGS_EXTRA ?=
LDFLAGS ?=
LDFLAGS_EXTRA ?=

BOOTSTRAP_TEST := $(BUILD_DIR)/test_bootstrap
OCRA_CORE_TEST := $(BUILD_DIR)/test_ocra_core
OCRA_VECTOR_TEST := $(BUILD_DIR)/test_ocra_vectors

.PHONY: clean gate-00 gate-01 test-bootstrap test-ocra-core

test-bootstrap: $(BOOTSTRAP_TEST)
	$(BOOTSTRAP_TEST)

test-ocra-core: $(OCRA_CORE_TEST) $(OCRA_VECTOR_TEST)
	$(OCRA_CORE_TEST)
	$(OCRA_VECTOR_TEST)

$(BOOTSTRAP_TEST): tests/test_bootstrap.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) $< -o $@ \
		$(LDFLAGS) $(LDFLAGS_EXTRA)

$(OCRA_CORE_TEST): tests/test_ocra_core.c ocra_suite.c ocra_core.c \
		secure_memory.c ocra_suite.h ocra_core.h secure_memory.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) tests/test_ocra_core.c \
		ocra_suite.c secure_memory.c ocra_core.c -o $@ -lcrypto $(LDFLAGS) \
		$(LDFLAGS_EXTRA)

$(OCRA_VECTOR_TEST): tests/test_ocra_vectors.c ocra_suite.c ocra_core.c \
		secure_memory.c ocra_suite.h ocra_core.h secure_memory.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) tests/test_ocra_vectors.c \
		ocra_suite.c secure_memory.c ocra_core.c -o $@ -lcrypto $(LDFLAGS) \
		$(LDFLAGS_EXTRA)

gate-00:
	$(MAKE) -C ../tests verify
	$(MAKE) clean
	$(MAKE) CC=gcc test-bootstrap
	$(MAKE) clean
	$(MAKE) CC=clang test-bootstrap

gate-01:
	$(MAKE) gate-00
	$(MAKE) clean
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-ocra-core
	$(MAKE) CC=clang BUILD_DIR=build/clang test-ocra-core
	$(MAKE) CC=clang BUILD_DIR=build/asan \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test-ocra-core
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 build/gcc/test_ocra_core
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 build/gcc/test_ocra_vectors

clean:
	$(RM) -r build
