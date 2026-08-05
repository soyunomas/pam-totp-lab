CC ?= cc

BUILD_DIR ?= build/$(notdir $(CC))
CPPFLAGS ?=
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic
CFLAGS_EXTRA ?=
LDFLAGS ?=
LDFLAGS_EXTRA ?=

BOOTSTRAP_TEST := $(BUILD_DIR)/test_bootstrap

.PHONY: clean gate-00 test-bootstrap

test-bootstrap: $(BOOTSTRAP_TEST)
	$(BOOTSTRAP_TEST)

$(BOOTSTRAP_TEST): tests/test_bootstrap.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) $< -o $@ \
		$(LDFLAGS) $(LDFLAGS_EXTRA)

gate-00:
	$(MAKE) -C ../tests verify
	$(MAKE) clean
	$(MAKE) CC=gcc test-bootstrap
	$(MAKE) clean
	$(MAKE) CC=clang test-bootstrap

clean:
	$(RM) -r build
