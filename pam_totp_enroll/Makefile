PYTHON ?= python3
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
PROGRAM := pam-totp-enroll
SOURCE := pam_totp_enroll.py

.PHONY: all help deps test verify install uninstall clean

all: verify

help:
	@echo "pam_totp_enroll"
	@echo "  make deps       Instala qrencode y python3 (Debian/Ubuntu/Mint)"
	@echo "  make test       Ejecuta pruebas unitarias y de flujo"
	@echo "  make verify     Compila sintácticamente y ejecuta las pruebas"
	@echo "  make install    Instala $(PROGRAM) en $(BINDIR)"
	@echo "  make uninstall  Desinstala $(PROGRAM)"

deps:
	sudo apt-get update
	sudo apt-get install -y python3 qrencode

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

verify:
	$(PYTHON) -m py_compile $(SOURCE) tests/test_pam_totp_enroll.py
	$(MAKE) test

install: verify
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(SOURCE) "$(DESTDIR)$(BINDIR)/$(PROGRAM)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(PROGRAM)"

clean:
	rm -rf -- __pycache__ tests/__pycache__
