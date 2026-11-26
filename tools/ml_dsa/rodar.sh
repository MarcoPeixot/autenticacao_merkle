#!/bin/sh
# Roda dentro do container. /fonte/ml_dsa é esta pasta; o argumento é o
# número de rodadas. Tudo sai no stdout, uma linha por item.
set -eu

echo "ambiente arquitetura: $(uname -m)"
echo "ambiente compilador: $(gcc --version | head -n 1)"
echo "ambiente openssl: $(openssl version)"
echo "ambiente imagem: $(. /etc/os-release && echo "$PRETTY_NAME")"

if ! gcc -O2 -Wall -Wextra -o /tmp/medir /fonte/ml_dsa/medir.c -lcrypto 2> /tmp/avisos.txt; then
    cat /tmp/avisos.txt >&2
    exit 1
fi
sed 's/^/aviso /' /tmp/avisos.txt

/tmp/medir "$1"
