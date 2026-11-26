#!/bin/sh
# Roda dentro do container. /fonte/patch é patch-v5/, /fonte/apoio é esta
# pasta e /trabalho é onde o script em Python deixa as entradas.
set -eu

etapa="$1"
saida=/trabalho/saida
mkdir -p "$saida"

if [ "$etapa" = "ferramenta" ]; then
    {
        echo "arquitetura: $(uname -m)"
        echo "compilador: $(gcc --version | head -n 1)"
        echo "openssl: $(openssl version)"
        echo "imagem: $(. /etc/os-release && echo "$PRETTY_NAME")"
    } > "$saida/ambiente.txt"

    # Mesmas flags do scripts/Makefile do patch, mais -Wall -Wextra.
    gcc -O2 -Wall -Wextra \
        -I/fonte/patch/scripts/include \
        -I/fonte/patch/tools/include/uapi \
        -o /tmp/modules-merkle-tree /fonte/patch/scripts/modules-merkle-tree.c \
        -lcrypto 2> "$saida/avisos-ferramenta.txt"

    for arvore in /trabalho/arvores/*/; do
        (cd "$arvore" && /tmp/modules-merkle-tree raiz.c .ko)
    done
fi

if [ "$etapa" = "verificador" ]; then
    # hashes.c sem alteração; os cabeçalhos de kernel/ trocam o que é do
    # kernel (SHA-256, macros, erros) pelo equivalente em espaço de usuário.
    gcc -O2 -Wall -Wextra \
        -I/fonte/apoio/kernel \
        -I/fonte/patch/include \
        -o /tmp/verificar /fonte/apoio/verificar.c /fonte/patch/kernel/module/hashes.c \
        -lcrypto 2> "$saida/avisos-verificador.txt"

    /tmp/verificar < /trabalho/casos.txt > "$saida/respostas.txt"
fi
