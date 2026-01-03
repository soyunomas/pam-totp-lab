# ==============================================================================
#  PAM SANDWICH - MAKEFILE (SECURE EDITION)
# ==============================================================================

# Nombre del binario final
BINARY_NAME := pam_sandwich.so

# Compilador y Flags de Seguridad (Audit Hardened)
CC          := gcc
# Se añade -Werror para cumplir Regla 30 (0 warnings permitidos)
# Se añade -fno-stack-protector para evitar conflictos con símbolos de PAM en algunos sistemas
CFLAGS      := -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2
LDFLAGS     := -shared -lpam -loath

# Detección automática del directorio de seguridad de PAM
ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

# Colores ANSI para una salida bonita en terminal
RED     := \033[1;31m
GREEN   := \033[1;32m
YELLOW  := \033[1;33m
BLUE    := \033[1;34m
CYAN    := \033[1;36m
RESET   := \033[0m

# ==============================================================================
# TARGETS (REGLAS)
# ==============================================================================

.PHONY: all help build deps install uninstall clean hints

all: build

# --- MENÚ DE AYUDA ---
help:
	@echo ""
	@echo "${CYAN}   🥪  PAM SANDWICH - MENÚ DE AYUDA  🥪${RESET}"
	@echo "${CYAN}==============================================${RESET}"
	@echo "  ${YELLOW}make deps${RESET}      Instala las dependencias (libpam0g-dev, liboath-dev)"
	@echo "  ${YELLOW}make build${RESET}     Compila el módulo .so (Modo Estricto)"
	@echo "  ${YELLOW}make install${RESET}   Instala en el sistema y muestra el MANUAL DE OPERACIONES"
	@echo "  ${YELLOW}make hints${RESET}     Muestra SOLO el Manual de Operaciones"
	@echo "  ${YELLOW}make uninstall${RESET} Elimina el módulo del sistema"
	@echo "  ${YELLOW}make clean${RESET}     Borra archivos compilados"
	@echo ""

# --- INSTALACIÓN DE DEPENDENCIAS ---
deps:
	@echo "${BLUE}[*] Instalando dependencias necesarias...${RESET}"
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev liboath-dev
	@echo "${GREEN}[OK] Dependencias instaladas.${RESET}"

# --- COMPILACIÓN ---
build:
	@echo "${BLUE}[*] Compilando $(BINARY_NAME) con flags de seguridad...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) pam_sandwich.c $(LDFLAGS)
	@echo "${GREEN}[OK] Compilación exitosa (Zero Warnings).${RESET}"

# --- INSTALACIÓN ---
install: build
	@echo "${BLUE}[*] Instalando en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then \
		echo "${RED}[ERROR] El directorio $(PAM_DIR) no existe.${RESET}"; \
		exit 1; \
	fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Instalado correctamente.${RESET}"
	@# Ejecutamos los hints automáticamente tras instalar
	@$(MAKE) -s hints

# --- DESINSTALACIÓN ---
uninstall:
	@echo "${BLUE}[*] Eliminando $(BINARY_NAME)...${RESET}"
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Módulo eliminado.${RESET}"

# --- LIMPIEZA ---
clean:
	@echo "${BLUE}[*] Limpiando...${RESET}"
	rm -f $(BINARY_NAME)
	@echo "${GREEN}[OK] Limpio.${RESET}"

# ==============================================================================
#  HINTS (MANUAL DE OPERACIONES - SECURE DEPLOYMENT)
# ==============================================================================
hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${YELLOW}         MANUAL DE OPERACIONES: DESPLIEGUE SEGURO PAM           ${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
	@echo "${BLUE}PASO 1: Configurar el archivo PAM de SSH${RESET}"
	@echo "  Ejecuta: ${GREEN}sudo nano /etc/pam.d/sshd${RESET}"
	@echo "  Añade esta línea AL PRINCIPIO del archivo (antes de @include common-auth):"
	@echo "  ------------------------------------------------------------"
	@echo "  ${RED}auth required $(PAM_DIR)/$(BINARY_NAME)${RESET}"
	@echo "  ------------------------------------------------------------"
	@echo "  ${CYAN}NOTA:${RESET} Si el usuario no tiene fichero o permisos mal, se ignora (Fail-Close)."
	@echo ""
	@echo "${BLUE}PASO 2: Configurar el servicio SSH${RESET}"
	@echo "  Ejecuta: ${GREEN}sudo nano /etc/ssh/sshd_config${RESET}"
	@echo "  Asegúrate de tener estas directivas:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${YELLOW}UsePAM yes${RESET}"
	@echo "  ${YELLOW}KbdInteractiveAuthentication yes${RESET}"
	@echo "  ${YELLOW}PasswordAuthentication no${RESET} (Para forzar el uso de PAM)"
	@echo "  ------------------------------------------------------------"
	@echo ""
	@echo "${BLUE}PASO 3: PREPARACIÓN DEL USUARIO (CRÍTICO)${RESET}"
	@echo "  Cada usuario debe ejecutar esto en su terminal:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${GREEN}cd ~${RESET}"
	@echo "  ${GREEN}echo 'TU_SECRETO_BASE32_AQUI' > .google_authenticator${RESET}"
	@echo "  ${RED}chmod 600 .google_authenticator${RESET}  <-- ¡OBLIGATORIO!"
	@echo "  ------------------------------------------------------------"
	@echo "  ${RED}⚠️  ATENCIÓN:${RESET} El secreto debe tener mín. 16 caracteres."
	@echo "  ${RED}⚠️  ATENCIÓN:${RESET} Si no haces 'chmod 600', el módulo rechazará el acceso."
	@echo ""
	@echo "${BLUE}PASO 4: Aplicar cambios${RESET}"
	@echo "  Ejecuta: ${GREEN}sudo systemctl restart ssh${RESET}"
	@echo ""
	@echo "${RED}¡ADVERTENCIA FINAL!${RESET}"
	@echo "  1. NO CIERRES tu sesión actual."
	@echo "  2. Abre una TERMINAL NUEVA y prueba a loguearte."
	@echo "  3. Recuerda el formato: ${YELLOW}PREFIJO(3) + PASSWORD + SUFIJO(3)${RESET}"
	@echo ""
