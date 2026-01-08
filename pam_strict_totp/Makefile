# ==============================================================================
#  PAM strict_totp - MAKEFILE (SECURE EDITION)
# ==============================================================================

BINARY_NAME := pam_strict_totp.so
CC          := gcc
CFLAGS      := -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2
LDFLAGS     := -shared -lpam -loath

# Detección de directorio PAM
ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

# Colores
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
	@echo "${CYAN}   🥪  PAM STRICT_TOTP - MENÚ  🥪${RESET}"
	@echo "  ${YELLOW}make deps${RESET}      Instala dependencias"
	@echo "  ${YELLOW}make build${RESET}     Compila"
	@echo "  ${YELLOW}make install${RESET}   Instala y muestra HINTS"
	@echo "  ${YELLOW}make hints${RESET}     Muestra instrucciones de configuración"
	@echo "  ${YELLOW}make uninstall${RESET} Desinstala"
	@echo "  ${YELLOW}make clean${RESET}     Limpia"
	@echo ""

deps:
	@echo "${BLUE}[*] Instalando dependencias...${RESET}"
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev liboath-dev

build:
	@echo "${BLUE}[*] Compilando $(BINARY_NAME)...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) pam_strict_totp.c $(LDFLAGS)
	@echo "${GREEN}[OK] Compilado.${RESET}"

install: build
	@echo "${BLUE}[*] Instalando en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then echo "${RED}[ERROR] Dir PAM no encontrado.${RESET}"; exit 1; fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Instalado.${RESET}"
	@$(MAKE) -s hints

uninstall:
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Eliminado.${RESET}"

clean:
	rm -f $(BINARY_NAME)

hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${YELLOW}         ⚠️  GUÍA DE DESPLIEGUE CRÍTICA  ⚠️           ${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
	@echo "${BLUE}1. SETUP DEL SERVIDOR (PAM)${RESET}"
	@echo "   Fichero: ${GREEN}/etc/pam.d/sshd${RESET}"
	@echo "   Añadir AL FINAL (o tras common-auth):"
	@echo "   ${RED}auth required $(PAM_DIR)/$(BINARY_NAME) nullok${RESET}"
	@echo ""
	@echo "${BLUE}2. SETUP DEL SERVIDOR (SSH)${RESET}"
	@echo "   Fichero: ${GREEN}/etc/ssh/sshd_config${RESET}"
	@echo "   ${YELLOW}KbdInteractiveAuthentication yes${RESET}"
	@echo "   ${YELLOW}UsePAM yes${RESET}"
	@echo "   ${YELLOW}PasswordAuthentication no${RESET} (Recomendado)"
	@echo "   Reinicia SSH: ${GREEN}sudo systemctl restart ssh${RESET}"
	@echo ""
	@echo "${BLUE}3. SETUP DEL USUARIO (OBLIGATORIO)${RESET}"
	@echo "   Cada usuario debe crear su fichero de secreto:"
	@echo "   ${GREEN}echo 'MI_SECRETO_BASE32' > ~/.google_authenticator${RESET}"
	@echo "   ${RED}chmod 600 ~/.google_authenticator${RESET}"
	@echo ""
	@echo "${RED}🛑 ERRORES COMUNES (LEER):${RESET}"
	@echo "   1. ${YELLOW}HORA:${RESET} Servidor y móvil deben tener la misma hora (NTP)."
	@echo "   2. ${YELLOW}PERMISOS:${RESET} Si el fichero no tiene chmod 600, EL ACCESO SE BLOQUEA."
	@echo "   3. ${YELLOW}FORMATO:${RESET} El secreto debe ser Base32 puro (A-Z, 2-7). SIN ESPACIOS."
	@echo "      Ejemplo válido:   JBSWY3DPEHPK3PXP"
	@echo "      Ejemplo inválido: JBSWY 3DPEH (Espacios) / 1890 (Números prohibidos)"
	@echo ""
