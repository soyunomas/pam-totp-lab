# ==============================================================================
#  PAM CHRONOGUARD - MAKEFILE (SECURE EDITION)
# ==============================================================================

BINARY_NAME := pam_chronoguard.so
CC          := gcc
# Flags de seguridad + Thread Safety (_REENTRANT)
CFLAGS      := -fPIC -fstack-protector-all -Wall -Wextra -Werror -O2 -D_REENTRANT
LDFLAGS     := -shared -lpam

# Detección automática del directorio de librerías PAM
ifneq ("$(wildcard /lib/x86_64-linux-gnu/security/.)","")
    PAM_DIR := /lib/x86_64-linux-gnu/security
else ifneq ("$(wildcard /usr/lib64/security/.)","")
    PAM_DIR := /usr/lib64/security
else
    PAM_DIR := /lib/security
endif

# Colores ANSI
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
	@echo "${CYAN}   ⏳ PAM CHRONOGUARD - MENÚ DE AYUDA  ⏳${RESET}"
	@echo "${CYAN}==============================================${RESET}"
	@echo "  ${YELLOW}make deps${RESET}      Instala dependencias (libpam-dev)"
	@echo "  ${YELLOW}make build${RESET}     Compila el módulo .so"
	@echo "  ${YELLOW}make install${RESET}   Instala y muestra instrucciones"
	@echo "  ${YELLOW}make hints${RESET}     Muestra el manual de configuración"
	@echo "  ${YELLOW}make uninstall${RESET} Elimina el módulo del sistema"
	@echo "  ${YELLOW}make clean${RESET}     Limpia binarios"
	@echo ""

deps:
	@echo "${BLUE}[*] Instalando dependencias...${RESET}"
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev
	@echo "${GREEN}[OK] Dependencias instaladas.${RESET}"

build:
	@echo "${BLUE}[*] Compilando $(BINARY_NAME)...${RESET}"
	$(CC) $(CFLAGS) -o $(BINARY_NAME) pam_chronoguard.c $(LDFLAGS)
	@echo "${GREEN}[OK] Compilación exitosa.${RESET}"

install: build
	@echo "${BLUE}[*] Instalando en $(PAM_DIR)...${RESET}"
	@if [ ! -d "$(PAM_DIR)" ]; then \
		echo "${RED}[ERROR] Directorio $(PAM_DIR) no existe.${RESET}"; \
		exit 1; \
	fi
	sudo cp $(BINARY_NAME) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Instalado.${RESET}"
	@$(MAKE) -s hints

uninstall:
	@echo "${BLUE}[*] Eliminando $(BINARY_NAME)...${RESET}"
	sudo rm -f $(PAM_DIR)/$(BINARY_NAME)
	@echo "${GREEN}[OK] Eliminado.${RESET}"

clean:
	@echo "${BLUE}[*] Limpiando...${RESET}"
	rm -f $(BINARY_NAME)
	@echo "${GREEN}[OK] Limpio.${RESET}"

# ==============================================================================
#  HINTS (MANUAL DE OPERACIONES ACTUALIZADO)
# ==============================================================================
hints:
	@echo ""
	@echo "${CYAN}================================================================${RESET}"
	@echo "${YELLOW}         MANUAL DE OPERACIONES: PAM CHRONOGUARD                 ${RESET}"
	@echo "${CYAN}================================================================${RESET}"
	@echo "${BLUE}PASO 1: Configurar PAM (/etc/pam.d/sshd)${RESET}"
	@echo "  Añade esta línea al PRINCIPIO del archivo:"
	@echo "  ${RED}auth required $(PAM_DIR)/$(BINARY_NAME)${RESET}"
	@echo ""
	@echo "${BLUE}PASO 2: Configurar SSH (/etc/ssh/sshd_config)${RESET}"
	@echo "  Asegúrate de tener: ${YELLOW}UsePAM yes${RESET} y ${YELLOW}KbdInteractiveAuthentication yes${RESET}"
	@echo ""
	@echo "${BLUE}PASO 3: Configurar Usuario (~/.chronoguard)${RESET}"
	@echo "  Crea el archivo con formato CLAVE=VALOR:"
	@echo "  ------------------------------------------------------------"
	@echo "  ${GREEN}echo \"PRE=HH\" > ~/.chronoguard${RESET}"
	@echo "  ${GREEN}echo \"POST=DDMM\" >> ~/.chronoguard${RESET}"
	@echo "  ${RED}chmod 600 ~/.chronoguard${RESET}  <-- ¡CRÍTICO!"
	@echo "  ------------------------------------------------------------"
	@echo "  ${CYAN}TOKENS VÁLIDOS:${RESET}"
	@echo "    HH (Hora 24h) | MI (Minutos) | DD (Día Mes)"
	@echo "    MM (Mes)      | YY (Año 2d)  | YYYY (Año 4d)"
	@echo "    WD (Día Semana 1-7)"
	@echo ""
	@echo "${BLUE}TROUBLESHOOTING:${RESET}"
	@echo "  Si fallas, revisa ${YELLOW}/var/log/auth.log${RESET}."
	@echo "  (El log de contraseñas ha sido desactivado por seguridad)."
	@echo ""
