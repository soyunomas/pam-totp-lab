# ==============================================================================
#  PAM 2-MAN RULE TOTP - MAKEFILE (SECURE EDITION)
# ==============================================================================

BINARY_NAME := pam_2man_totp.so
SOURCE_NAME := pam_2man_totp.c
COMMON_SOURCE := ../pam_common/totp_replay.c
CC          := gcc
# Security: Stack protection, PIE, Fortify Source, Strict Warnings
CFLAGS      := -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
               -Wall -Wextra -Werror -O2
LDFLAGS     := -shared -lpam -loath -pthread

# Detección automática de directorio PAM (Distro-agnostic)
ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

# Colores para la terminal
RED     := \033[1;31m
GREEN   := \033[1;32m
YELLOW  := \033[1;33m
BLUE    := \033[1;34m
CYAN    := \033[1;36m
RESET   := \033[0m

.PHONY: all help build deps install uninstall clean hints

all: build

help:
	@echo ""
	@echo "${CYAN}   🔐  PAM 2-MAN RULE TOTP - MENÚ DE CONTROL  🔐${RESET}"
	@echo "  ${YELLOW}make deps${RESET}      Instala dependencias (libpam, liboath)"
	@echo "  ${YELLOW}make build${RESET}     Compila el módulo de alta seguridad"
	@echo "  ${YELLOW}make install${RESET}   Instala en $(PAM_DIR) y muestra GUÍA"
	@echo "  ${YELLOW}make hints${RESET}     Muestra instrucciones de despliegue SSH"
	@echo "  ${YELLOW}make uninstall${RESET} Desinstala el módulo"
	@echo "  ${YELLOW}make clean${RESET}     Limpia binarios"
	@echo ""

deps:
	@echo "${BLUE}[*] Instalando dependencias...${RESET}"
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev liboath-dev

build:
	@echo "${BLUE}[*] Compilando $(BINARY_NAME) desde $(SOURCE_NAME)...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) $(SOURCE_NAME) $(COMMON_SOURCE) $(LDFLAGS)
	@echo "${GREEN}[OK] Compilación exitosa.${RESET}"

install: build
	@echo "${BLUE}[*] Instalando en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then echo "${RED}[ERROR] Dir PAM no encontrado.${RESET}"; exit 1; fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chown root:root $(PAM_DIR)/$(BINARY_NAME)
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Módulo instalado.${RESET}"
	@$(MAKE) -s hints

uninstall:
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Eliminado del sistema.${RESET}"

clean:
	rm -f $(BINARY_NAME)

hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${YELLOW}      🚀 GUÍA DE DESPLIEGUE: SSH TWO-MAN RULE (2 PERSONAS) 🚀${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
	@echo "${BLUE}1. CONFIGURACIÓN PAM (SSH)${RESET}"
	@echo "   Fichero: ${GREEN}/etc/pam.d/sshd${RESET}"
	@echo "   Añadir (después de @include common-auth):"
	@echo "   ${RED}auth required $(BINARY_NAME)${RESET}"
	@echo ""
	@echo "${BLUE}2. CONFIGURACIÓN SSHD${RESET}"
	@echo "   Fichero: ${GREEN}/etc/ssh/sshd_config${RESET}"
	@echo "   ${YELLOW}KbdInteractiveAuthentication yes${RESET}"
	@echo "   ${YELLOW}UsePAM yes${RESET}"
	@echo "   ${YELLOW}PasswordAuthentication no${RESET} (Opcional, recomendado)"
	@echo "   Reiniciar: ${GREEN}sudo systemctl restart ssh${RESET}"
	@echo ""
	@echo "${BLUE}3. REQUISITOS DE USUARIOS (CRÍTICO)${RESET}"
	@echo "   A) ${YELLOW}Usuario 1 (Tú):${RESET} Debes tener tu fichero secreto."
	@echo "   B) ${YELLOW}Usuario 2 (Autorizador):${RESET}"
	@echo "      - Debe existir en el sistema y tener su fichero secreto."
	@echo "      - Debe pertenecer al grupo ${RED}wheel${RESET} (o sudo)."
	@echo "      - Comando: ${GREEN}sudo usermod -aG wheel <usuario2>${RESET}"
	@echo ""
	@echo "${BLUE}4. GENERACIÓN DE SECRETOS (Para ambos usuarios)${RESET}"
	@echo "   ${GREEN}echo 'MI_SECRETO_BASE32' > ~/.google_authenticator${RESET}"
	@echo "   ${RED}chmod 600 ~/.google_authenticator${RESET}"
	@echo ""
	@echo "${CYAN}----------------------------------------------------------------${RESET}"
	@echo "${YELLOW}💡 FLUJO DE LOGIN ESPERADO:${RESET}"
	@echo "   1. Password de Usuario 1"
	@echo "   2. TOTP de Usuario 1"
	@echo "   3. Nombre del Usuario 2 (El Autorizador)"
	@echo "   4. TOTP del Usuario 2"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
