BINARY_NAME := pam_totp_domains.so
COMMON_SOURCE := ../pam_common/totp_replay.c
SOURCES := pam_totp_domains.c domains.c secret_file.c $(COMMON_SOURCE)
CC ?= gcc
CFLAGS := -std=c11 -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2
LDFLAGS := -shared -Wl,-z,relro,-z,now -lpam -loath -pthread

ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

.PHONY: all deps build test verify install uninstall clean hints

all: build

deps:
	sudo apt-get update
	sudo apt-get install -y build-essential clang libpam0g-dev liboath-dev valgrind binutils

build:
	$(CC) $(CFLAGS) -o $(BINARY_NAME) $(SOURCES) $(LDFLAGS)

test:
	./verify.sh test

verify:
	./verify.sh

install: build
	@if [ ! -d "$(PAM_DIR)" ]; then echo "Directorio PAM no encontrado"; exit 1; fi
	sudo install -o root -g root -m 0644 $(BINARY_NAME) $(PAM_DIR)/$(BINARY_NAME)
	@$(MAKE) -s hints

uninstall:
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)

clean:
	rm -rf -- build $(BINARY_NAME)

hints:
	@echo "Crea ~/.pam_totp_domains con modo 0700."
	@echo "Añade secretos distintos: sshd.secret, sudo.secret, login.secret y su.secret, con modo 0600."
	@echo "Configura PAM, por ejemplo: auth required pam_totp_domains.so"
	@echo "Mantén una sesión root abierta durante las pruebas."
