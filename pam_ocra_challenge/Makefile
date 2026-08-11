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
CHALLENGE_TEST := $(BUILD_DIR)/test_challenge
SECRET_STORE_TEST := $(BUILD_DIR)/test_secret_store
SECRET_PARSER_FUZZ := $(BUILD_DIR)/fuzz_secret_parser
RATE_LIMIT_TEST := $(BUILD_DIR)/test_rate_limit
CONCURRENCY_TEST := $(BUILD_DIR)/test_concurrency
CLIENT_TEST := $(BUILD_DIR)/test_client
OCRA_CLIENT := $(BUILD_DIR)/ocra-client
ENROLL_TEST := $(BUILD_DIR)/test_enroll
OCRA_ENROLL := $(BUILD_DIR)/ocra-enroll
MODULE_TEST := $(BUILD_DIR)/test_module
PAM_MODULE := $(BUILD_DIR)/pam_ocra_challenge.so
SECRET_STORE_PRODUCTION_OBJECTS := $(BUILD_DIR)/scope.production.o \
	$(BUILD_DIR)/secret_store.production.o
RATE_LIMIT_PRODUCTION_OBJECTS := $(BUILD_DIR)/scope.production.o \
	$(BUILD_DIR)/challenge.production.o $(BUILD_DIR)/rate_limit.production.o
DEVICE_TEST_IMAGE ?= postgres:15

.PHONY: clean gate-00 gate-01 gate-02 gate-03 gate-04 test-bootstrap test-ocra-core \
	test-challenge test-secret-store sanitize-challenge valgrind-challenge \
	sanitize-secret-store valgrind-secret-store fuzz-secret-parser \
	test-secret-store-device compile-secret-store-production test-rate-limit \
	test-rate-limit-owner test-concurrency sanitize-rate-limit valgrind-rate-limit \
	compile-rate-limit-production test-client sanitize-client valgrind-client \
	test-enroll test-enroll-owner sanitize-enroll valgrind-enroll smoke-enroll \
	compile-enroll-production test-module compile-module-production gate-05 gate-06

test-bootstrap: $(BOOTSTRAP_TEST)
	$(BOOTSTRAP_TEST)

test-ocra-core: $(OCRA_CORE_TEST) $(OCRA_VECTOR_TEST)
	$(OCRA_CORE_TEST)
	$(OCRA_VECTOR_TEST)

test-challenge: $(CHALLENGE_TEST)
	$(CHALLENGE_TEST)

test-secret-store: $(SECRET_STORE_TEST)
	OCRA_TEST_ALLOW_MKNOD_SKIP=yes $(SECRET_STORE_TEST)

test-rate-limit: $(RATE_LIMIT_TEST)
	$(RATE_LIMIT_TEST)

test-concurrency: $(CONCURRENCY_TEST)
	$(CONCURRENCY_TEST)

test-client: $(CLIENT_TEST) $(OCRA_CLIENT)
	OCRA_CLIENT_BIN="$(abspath $(OCRA_CLIENT))" $(CLIENT_TEST)

test-enroll: $(ENROLL_TEST) $(OCRA_ENROLL)
	$(ENROLL_TEST)

test-module: $(MODULE_TEST)
	$(MODULE_TEST)

compile-module-production: $(PAM_MODULE)

test-enroll-owner: $(ENROLL_TEST)
	docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
		--cap-add DAC_OVERRIDE --cap-add FOWNER --pids-limit 64 \
		--security-opt no-new-privileges --read-only \
		--tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
		-e OCRA_TEST_REQUIRE_ENROLL_OWNER_MISMATCH=yes \
		-v "$(abspath $(ENROLL_TEST)):/test_enroll:ro" \
		$(DEVICE_TEST_IMAGE) /test_enroll

smoke-enroll: $(OCRA_ENROLL)
	docker run --rm --network none --cap-drop ALL --pids-limit 64 \
		--security-opt no-new-privileges --read-only --user 65534:65534 \
		-v "$(abspath $(OCRA_ENROLL)):/ocra-enroll:ro" \
		--entrypoint /bin/sh $(DEVICE_TEST_IMAGE) -ec \
		'! /ocra-enroll inspect --user nobody --service sudo'
	docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
		--cap-add DAC_OVERRIDE --pids-limit 64 \
		--security-opt no-new-privileges --read-only \
		--tmpfs /etc/security:rw,nosuid,nodev,size=16m,mode=0700 \
		--tmpfs /run:rw,nosuid,nodev,size=16m,mode=0755 \
		--tmpfs /client:rw,nosuid,nodev,size=16m,mode=0700 \
		-v "$(abspath $(OCRA_ENROLL)):/ocra-enroll:ro" \
		--entrypoint /bin/sh $(DEVICE_TEST_IMAGE) -ec \
		'uid="$$(id -u nobody)"; gid="$$(id -g nobody)"; \
		 chmod 0700 /client; chown "$$uid:$$gid" /client; \
		 /ocra-enroll add --user nobody --service sudo \
			--client-profile /client/nobody-sudo.conf; \
		 server="/etc/security/pam-ocra/users/$$uid/sudo.conf"; \
		 test -f "$$server"; test -f /client/nobody-sudo.conf; \
		 cmp "$$server" /client/nobody-sudo.conf; \
		 test "$$(stat -c %a "$$server")" = 600; \
		 test "$$(stat -c %a /client/nobody-sudo.conf)" = 600; \
		 test "$$(stat -c %u /client/nobody-sudo.conf)" = "$$uid"; \
		 metadata="$$(/ocra-enroll inspect --user nobody --service sudo)"; \
		 case "$$metadata" in \
			*"uid=$$uid service=sudo enabled=yes key_id="*) ;; *) exit 1 ;; \
		 esac; \
		 case "$$metadata" in *secret=*|*suite=*) exit 1 ;; esac; \
		 /ocra-enroll revoke --user nobody --service sudo; \
		 test ! -e "$$server"; test -f /client/nobody-sudo.conf'

test-rate-limit-owner: $(RATE_LIMIT_TEST)
	docker run --rm --network none --cap-drop ALL --cap-add CHOWN \
		--security-opt no-new-privileges --read-only \
		--tmpfs /tmp:rw,nosuid,size=16m,mode=1777 \
		-e OCRA_TEST_REQUIRE_OWNER_MISMATCH=yes \
		-v "$(abspath $(RATE_LIMIT_TEST)):/test_rate_limit:ro" \
		$(DEVICE_TEST_IMAGE) /test_rate_limit

test-secret-store-device: $(SECRET_STORE_TEST)
	docker run --rm --network none --cap-drop ALL --cap-add MKNOD \
		--security-opt no-new-privileges --read-only \
		--tmpfs /tmp:rw,nosuid,size=16m,mode=1777 \
		-v "$(abspath $(SECRET_STORE_TEST)):/test_secret_store:ro" \
		$(DEVICE_TEST_IMAGE) /test_secret_store

compile-secret-store-production: $(SECRET_STORE_PRODUCTION_OBJECTS)

compile-rate-limit-production: $(RATE_LIMIT_PRODUCTION_OBJECTS)

fuzz-secret-parser: $(SECRET_PARSER_FUZZ)
	$(SECRET_PARSER_FUZZ)

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

$(CHALLENGE_TEST): tests/test_challenge.c challenge.c challenge.h ocra_core.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING $(CFLAGS) $(CFLAGS_EXTRA) \
		tests/test_challenge.c challenge.c -o $@ $(LDFLAGS) $(LDFLAGS_EXTRA)

$(SECRET_STORE_TEST): tests/test_secret_store.c scope.c secret_store.c \
		scope.h secret_store.h secure_memory.c secure_memory.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING $(CFLAGS) $(CFLAGS_EXTRA) \
		tests/test_secret_store.c scope.c secret_store.c secure_memory.c -o $@ \
		-lcrypto $(LDFLAGS) $(LDFLAGS_EXTRA)

$(SECRET_PARSER_FUZZ): tests/fuzz_secret_parser.c scope.c secret_store.c \
		scope.h secret_store.h secure_memory.c secure_memory.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING $(CFLAGS) $(CFLAGS_EXTRA) \
		tests/fuzz_secret_parser.c scope.c secret_store.c secure_memory.c -o $@ \
		-lcrypto $(LDFLAGS) $(LDFLAGS_EXTRA)

$(RATE_LIMIT_TEST): tests/test_rate_limit.c rate_limit.c rate_limit.h scope.c \
		scope.h challenge.c challenge.h secret_store.h ocra_core.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING $(CFLAGS) $(CFLAGS_EXTRA) \
		tests/test_rate_limit.c rate_limit.c scope.c challenge.c -o $@ \
		$(LDFLAGS) $(LDFLAGS_EXTRA)

$(CONCURRENCY_TEST): tests/test_concurrency.c rate_limit.c rate_limit.h \
		scope.c scope.h challenge.c challenge.h secret_store.h ocra_core.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING $(CFLAGS) $(CFLAGS_EXTRA) \
		tests/test_concurrency.c rate_limit.c scope.c challenge.c -o $@ \
		$(LDFLAGS) $(LDFLAGS_EXTRA)

$(CLIENT_TEST): tests/test_client.c tools/ocra_client.c tools/ocra_client.h \
		challenge.c challenge.h ocra_core.c ocra_core.h ocra_suite.c ocra_suite.h secret_store.c \
		secret_store.h secure_memory.c secure_memory.h scope.c scope.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING -DOCRA_CLIENT_NO_MAIN $(CFLAGS) \
		$(CFLAGS_EXTRA) tests/test_client.c tools/ocra_client.c challenge.c ocra_suite.c \
		secure_memory.c ocra_core.c scope.c secret_store.c -o $@ -lcrypto \
		$(LDFLAGS) $(LDFLAGS_EXTRA)

$(OCRA_CLIENT): tools/ocra_client.c tools/ocra_client.h ocra_core.c \
		ocra_core.h ocra_suite.c ocra_suite.h secret_store.c secret_store.h \
		secure_memory.c secure_memory.h scope.c scope.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) tools/ocra_client.c \
		ocra_suite.c secure_memory.c ocra_core.c scope.c secret_store.c -o $@ \
		-lcrypto $(LDFLAGS) $(LDFLAGS_EXTRA)

$(ENROLL_TEST): tests/test_enroll.c tools/ocra_enroll.c \
		tools/ocra_enroll.h secret_store.c secret_store.h secure_memory.c \
		secure_memory.h scope.c scope.h ocra_core.c ocra_core.h ocra_suite.c \
		ocra_suite.h challenge.c challenge.h rate_limit.c rate_limit.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DOCRA_TESTING -DOCRA_ENROLL_NO_MAIN $(CFLAGS) \
		$(CFLAGS_EXTRA) tests/test_enroll.c tools/ocra_enroll.c secret_store.c \
		secure_memory.c scope.c ocra_core.c ocra_suite.c challenge.c \
		rate_limit.c -o $@ -lcrypto $(LDFLAGS) $(LDFLAGS_EXTRA)

$(OCRA_ENROLL): tools/ocra_enroll.c tools/ocra_enroll.h secret_store.c \
		secret_store.h secure_memory.c secure_memory.h scope.c scope.h \
		ocra_core.c ocra_core.h ocra_suite.c ocra_suite.h challenge.c \
		challenge.h rate_limit.c rate_limit.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) tools/ocra_enroll.c \
		secret_store.c secure_memory.c scope.c ocra_core.c ocra_suite.c \
		challenge.c rate_limit.c -o $@ -lcrypto $(LDFLAGS) \
		$(LDFLAGS_EXTRA)

$(MODULE_TEST): tests/test_module.c pam_ocra_challenge.c \
		tests/stubs/security/pam_modules.h \
		tests/stubs/security/pam_ext.h ocra_core.c ocra_core.h ocra_suite.c \
		ocra_suite.h secure_memory.c secure_memory.h secret_store.h \
		rate_limit.h scope.c scope.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -Itests/stubs \
		tests/test_module.c pam_ocra_challenge.c ocra_core.c ocra_suite.c \
		secure_memory.c scope.c -o $@ -lcrypto $(LDFLAGS) $(LDFLAGS_EXTRA)

$(PAM_MODULE): pam_ocra_challenge.c ocra_core.c ocra_core.h ocra_suite.c \
		ocra_suite.h secure_memory.c secure_memory.h secret_store.c \
		secret_store.h rate_limit.c rate_limit.h challenge.c challenge.h \
		scope.c scope.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -fPIC -shared \
		pam_ocra_challenge.c ocra_core.c ocra_suite.c secure_memory.c \
		secret_store.c rate_limit.c challenge.c scope.c -o $@ -lpam -lcrypto \
		-Wl,-z,relro,-z,now $(LDFLAGS) $(LDFLAGS_EXTRA)

compile-enroll-production: $(OCRA_ENROLL)

$(BUILD_DIR)/scope.production.o: scope.c scope.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -c scope.c -o $@

$(BUILD_DIR)/secret_store.production.o: secret_store.c secret_store.h scope.h \
		secure_memory.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -c secret_store.c -o $@

$(BUILD_DIR)/challenge.production.o: challenge.c challenge.h ocra_core.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -c challenge.c -o $@

$(BUILD_DIR)/rate_limit.production.o: rate_limit.c rate_limit.h scope.h \
		challenge.h secret_store.h ocra_core.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_EXTRA) -c rate_limit.c -o $@

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

sanitize-challenge:
	$(MAKE) CC=clang BUILD_DIR=build/asan \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test-challenge

valgrind-challenge:
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-challenge
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 build/gcc/test_challenge

gate-02:
	$(MAKE) gate-01
	$(MAKE) CC=gcc test-challenge
	$(MAKE) CC=clang test-challenge
	$(MAKE) sanitize-challenge
	$(MAKE) valgrind-challenge

sanitize-secret-store:
	$(MAKE) CC=clang BUILD_DIR=build/asan-secret-store \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test-secret-store

valgrind-secret-store:
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-secret-store
	OCRA_TEST_ALLOW_MKNOD_SKIP=yes valgrind \
		--leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 \
		build/gcc/test_secret_store

gate-03: gate-02
	$(MAKE) clean
	$(MAKE) CC=gcc BUILD_DIR=build/gcc-production \
		compile-secret-store-production
	$(MAKE) CC=clang BUILD_DIR=build/clang-production \
		compile-secret-store-production
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-secret-store
	$(MAKE) CC=clang BUILD_DIR=build/clang test-secret-store
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-secret-store-device
	$(MAKE) sanitize-secret-store
	$(MAKE) valgrind-secret-store
	$(MAKE) CC=gcc BUILD_DIR=build/fuzz fuzz-secret-parser

sanitize-rate-limit:
	$(MAKE) CC=clang BUILD_DIR=build/asan-rate-limit \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' \
		test-rate-limit test-concurrency

valgrind-rate-limit:
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-rate-limit test-concurrency
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 \
		build/gcc/test_rate_limit
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 \
		build/gcc/test_concurrency

sanitize-client:
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) CC=clang BUILD_DIR=build/asan-client \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test-client

valgrind-client:
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-client
	OCRA_CLIENT_BIN="$(abspath build/gcc/ocra-client)" valgrind \
		--trace-children=yes \
		--log-file=build/gcc/valgrind-client.%p.log \
		--leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 build/gcc/test_client
	cat build/gcc/valgrind-client.*.log

gate-04: gate-03
	$(MAKE) clean
	$(MAKE) CC=gcc BUILD_DIR=build/gcc-production \
		compile-rate-limit-production
	$(MAKE) CC=clang BUILD_DIR=build/clang-production \
		compile-rate-limit-production
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-rate-limit test-concurrency
	$(MAKE) CC=clang BUILD_DIR=build/clang test-rate-limit test-concurrency
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-rate-limit-owner
	$(MAKE) sanitize-rate-limit
	$(MAKE) valgrind-rate-limit

gate-05: gate-04
	$(MAKE) clean
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-client
	$(MAKE) CC=clang BUILD_DIR=build/clang test-client
	$(MAKE) sanitize-client
	$(MAKE) valgrind-client

sanitize-enroll:
	ASAN_OPTIONS=detect_leaks=0 $(MAKE) CC=clang BUILD_DIR=build/asan-enroll \
		CFLAGS_EXTRA='-O1 -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS_EXTRA='-fsanitize=address,undefined' test-enroll

valgrind-enroll:
	$(MAKE) CC=gcc BUILD_DIR=build/gcc test-enroll
	valgrind --leak-check=full --show-leak-kinds=all \
		--errors-for-leak-kinds=all --error-exitcode=99 \
		build/gcc/test_enroll

gate-06: gate-05
	$(MAKE) clean
	$(MAKE) CC=gcc BUILD_DIR=build/gcc compile-enroll-production test-enroll \
		test-enroll-owner smoke-enroll
	$(MAKE) CC=clang BUILD_DIR=build/clang compile-enroll-production \
		test-enroll
	$(MAKE) sanitize-enroll
	$(MAKE) valgrind-enroll

clean:
	$(RM) -r build
