# ==============================================================================
#  PAM PARTIAL KEY (BANKING STYLE) - MAKEFILE (SECURE EDITION)
# ==============================================================================

# Nombre de los binarios
BINARY_NAME  := pam_partial_key.so
MANAGER_NAME := pk_manager

# Compilador y Flags de Seguridad (Audit Hardened)
CC          := gcc
# Regla 30: Zero Warnings. -Werror es obligatorio.
CFLAGS      := -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2
# Flags para el módulo PAM (.so)
LDFLAGS_PAM := -shared -lpam -lcrypto
# Flags para la herramienta de gestión (binario normal)
LDFLAGS_BIN := -lcrypto

# Detección automática del directorio de seguridad de PAM
ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

# Directorio para herramientas de usuario
BIN_DIR := /usr/local/bin

# Colores ANSI para salida profesional
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
	@echo "${CYAN}   🏦  PAM PARTIAL KEY - MENÚ DE AYUDA  🏦${RESET}"
	@echo "${CYAN}==============================================${RESET}"
	@echo "  ${YELLOW}make deps${RESET}      Instala dependencias (libpam0g-dev, libssl-dev)"
	@echo "  ${YELLOW}make build${RESET}     Compila el módulo y el gestor de claves (Strict Mode)"
	@echo "  ${YELLOW}make install${RESET}   Instala en el sistema y muestra el MANUAL BANCARIO"
	@echo "  ${YELLOW}make hints${RESET}     Muestra SOLO el Manual de Operaciones"
	@echo "  ${YELLOW}make uninstall${RESET} Elimina el módulo y el gestor del sistema"
	@echo "  ${YELLOW}make clean${RESET}     Borra archivos compilados"
	@echo ""

# --- INSTALACIÓN DE DEPENDENCIAS ---
deps:
	@echo "${BLUE}[*] Instalando dependencias necesarias (OpenSSL & PAM)...${RESET}"
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev libssl-dev
	@echo "${GREEN}[OK] Dependencias instaladas.${RESET}"

# --- COMPILACIÓN ---
build:
	@echo "${BLUE}[*] Compilando Módulo PAM ($(BINARY_NAME))...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) pam_partial_key.c $(LDFLAGS_PAM)
	
	@echo "${BLUE}[*] Compilando Gestor de Claves ($(MANAGER_NAME))...${RESET}"
	$(CC) $(CFLAGS) -o $(MANAGER_NAME) pk_manager.c $(LDFLAGS_BIN)
	
	@echo "${GREEN}[OK] Compilación exitosa (Zero Warnings).${RESET}"

# --- INSTALACIÓN ---
install: build
	@echo "${BLUE}[*] Instalando Módulo en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then \
		echo "${RED}[ERROR] El directorio $(PAM_DIR) no existe.${RESET}"; \
		exit 1; \
	fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	
	@echo "${BLUE}[*] Instalando Gestor en $(BIN_DIR)...${RESET}"
	sudo cp $(MANAGER_NAME) $(BIN_DIR)/
	sudo chmod 755 $(BIN_DIR)/$(MANAGER_NAME)
	
	@echo "${GREEN}[OK] Instalación completada.${RESET}"
	@# Ejecutamos los hints automáticamente
	@$(MAKE) -s hints

# --- DESINSTALACIÓN ---
uninstall:
	@echo "${BLUE}[*] Eliminando $(BINARY_NAME) y $(MANAGER_NAME)...${RESET}"
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	sudo rm -f $(BIN_DIR)/$(MANAGER_NAME)
	@echo "${GREEN}[OK] Componentes eliminados.${RESET}"

# --- LIMPIEZA ---
clean:
	@echo "${BLUE}[*] Limpiando...${RESET}"
	rm -f $(BINARY_NAME) $(MANAGER_NAME)
	@echo "${GREEN}[OK] Limpio.${RESET}"

# ==============================================================================
#  HINTS (MANUAL DE OPERACIONES - BANKING SECURITY)
# ==============================================================================
hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${YELLOW}      MANUAL DE OPERACIONES: AUTENTICACIÓN BANCARIA (PARCIAL)   ${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo ""
	@echo "${BLUE}PASO 1: Generación de Clave (USUARIO)${RESET}"
	@echo "  Cada usuario debe definir su 'Clave Maestra' ejecutando:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${GREEN}pk_manager${RESET}"
	@echo "  ------------------------------------------------------------"
	@echo "  El sistema pedirá una contraseña larga (ej. 'MiPerroSeLlamaFirulais123')"
	@echo "  y guardará los hashes posicionales de forma segura."
	@echo ""
	@echo "${BLUE}PASO 2: Configurar el archivo PAM de SSH${RESET}"
	@echo "  Ejecuta: ${GREEN}sudo nano /etc/pam.d/sshd${RESET}"
	@echo "  Añade esta línea al PRINCIPIO (para probar solo esto) o después de common-auth:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${RED}auth required $(PAM_DIR)/$(BINARY_NAME)${RESET}"
	@echo "  ------------------------------------------------------------"
	@echo ""
	@echo "${BLUE}PASO 3: Configurar SSH${RESET}"
	@echo "  Asegúrate en ${GREEN}/etc/ssh/sshd_config${RESET} de tener:"
	@echo "  ${YELLOW}UsePAM yes${RESET}"
	@echo "  ${YELLOW}ChallengeResponseAuthentication yes${RESET}"
	@echo ""
	@echo "${BLUE}PASO 4: Aplicar Cambios (CRÍTICO)${RESET}"
	@echo "  Para que la configuración surta efecto, reinicia el servicio:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${GREEN}sudo systemctl restart ssh${RESET}"
	@echo "  ------------------------------------------------------------"
	@echo ""
	@echo "${BLUE}PASO 5: PRUEBA DE LOGIN${RESET}"
	@echo "  Al loguearte, el sistema te dirá algo como:"
	@echo "  ${YELLOW}Posiciones [2] [5] [10]:${RESET}"
	@echo "  Debes introducir SOLO esos caracteres de tu clave maestra."
	@echo "  (ej: 'i', 'r', 'L' -> input: 'irL')"
	@echo ""
	@echo "${RED}¡ADVERTENCIA FINAL!${RESET}"
	@echo "  1. NO CIERRES tu sesión actual."
	@echo "  2. Abre una TERMINAL NUEVA y prueba a loguearte."
	@echo "  3. Si falla, comenta la línea en /etc/pam.d/sshd y reinicia ssh."
	@echo ""
