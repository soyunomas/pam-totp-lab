# ==============================================================================
#  PAM SCHOOL SCHEDULE - MAKEFILE (SSH EDITION)
# ==============================================================================

BINARY_NAME := pam_school_schedule.so
CC          := gcc
# Flags de seguridad estricta
CFLAGS      := -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2 -D_GNU_SOURCE
LDFLAGS     := -shared -lpam

# Detección de directorios
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
BOLD    := \033[1m

.PHONY: all build install uninstall clean hints

all: build

build:
	@echo "${BLUE}[*] Compilando...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) pam_school_schedule.c $(LDFLAGS)
	@echo "${GREEN}[OK] Compilado.${RESET}"

install: build
	@echo "${BLUE}[*] Instalando en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then echo "${RED}Error: $(PAM_DIR) no existe${RESET}"; exit 1; fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Instalado.${RESET}"
	@$(MAKE) -s hints

uninstall:
	@echo "${BLUE}[*] Eliminando $(BINARY_NAME) del sistema...${RESET}"
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Archivo binario eliminado.${RESET}"
	@echo "${YELLOW}[!] RECUERDA: Debes borrar manualmente la línea añadida en /etc/pam.d/sshd${RESET}"

clean:
	rm -f $(BINARY_NAME)

# ==============================================================================
#  HINTS: CONFIGURACIÓN SOLO PARA SSH
# ==============================================================================
hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${BOLD}           GUÍA DE CONFIGURACIÓN PARA SSH               ${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
	@echo "${YELLOW}1. EDITA EL PAM DE SSH:${RESET}"
	@echo "   ${GREEN}sudo nano /etc/pam.d/sshd${RESET}"
	@echo ""
	@echo "   Añade la línea ${RED}ROJA${RESET} al final o después del common-auth:"
	@echo "   ------------------------------------------------------------"
	@echo "   @include common-auth"
	@echo "   ${RED}auth required $(PAM_DIR)/$(BINARY_NAME) nullok${RESET}"
	@echo "   ------------------------------------------------------------"
	@echo "   (El 'nullok' permite entrar a usuarios que no tengan horario configurado)"
	@echo ""
	@echo "${YELLOW}2. ACTIVA PAM EN EL SERVIDOR SSH:${RESET}"
	@echo "   ${GREEN}sudo nano /etc/ssh/sshd_config${RESET}"
	@echo "   Asegúrate de tener estas opciones:"
	@echo "   ------------------------------------------------------------"
	@echo "   UsePAM yes"
	@echo "   KbdInteractiveAuthentication yes"
	@echo "   ------------------------------------------------------------"
	@echo ""
	@echo "${YELLOW}3. REINICIA Y PRUEBA:${RESET}"
	@echo "   ${GREEN}sudo systemctl restart ssh${RESET}"
	@echo ""
	@echo "${BOLD}   ¡NO CIERRES TU SESIÓN ACTUAL HASTA COMPROBAR QUE FUNCIONA!${RESET}"
	@echo ""
