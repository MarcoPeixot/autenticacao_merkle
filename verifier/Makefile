PKG_CONFIG ?= pkg-config
PYTHON ?= python3
BUILD_DIR ?= build
CFLAGS ?= -O2
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libcrypto)
LDLIBS += $(shell $(PKG_CONFIG) --libs libcrypto)

VERIFICADOR = $(BUILD_DIR)/verificar
VARIANTE = $(BUILD_DIR)/verificar-enderecos
FONTES = main.c merkle.c mrauth.c formatos.c arquivos.c
CABECALHOS = merkle.h mrauth.h formatos.h arquivos.h bytes.h

.PHONY: all enderecos test
all: $(VERIFICADOR)
enderecos: $(VARIANTE)

$(VARIANTE): DEFINES = -DMERKLE_ENDERECOS

$(VERIFICADOR) $(VARIANTE): $(FONTES) $(CABECALHOS) Makefile
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(DEFINES) $(CFLAGS) -std=c11 -Wall -Wextra -Wpedantic $(LDFLAGS) $(FONTES) $(LDLIBS) -o "$@"

test: $(VERIFICADOR) $(VARIANTE)
	cd .. && $(PYTHON) -B -m tools.comparar_verificador "$(abspath $(VERIFICADOR))"
	cd .. && $(PYTHON) -B -m tools.comparar_verificador "$(abspath $(VARIANTE))"
	cd .. && $(PYTHON) -B -m tools.testar_mrauth "$(abspath $(VERIFICADOR))" "$(abspath $(VARIANTE))"
