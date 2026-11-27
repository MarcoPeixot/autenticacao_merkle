"""Compila e testa o verificador em C no mesmo Debian 13 da comparação com o patch.

Roda ``make -C verifier test`` duas vezes: na compilação normal e com
AddressSanitizer e UBSan, com aviso do compilador tratado como erro. Cada
rodada compila as duas variantes (padrão e com endereços), compara a raiz
única com o Python nos 100 vetores e roda os casos de múltiplas raízes nos três
conjuntos ML-DSA.

O verificador precisa do OpenSSL 3.5 ou mais novo, que o macOS não tem. O
repositório entra no container só para leitura e a compilação fica no /tmp do
container, então a pasta não muda.

Precisa de Docker. Uso, a partir da raiz do repositório:

    python3 -m tools.testar_verificador
"""

from __future__ import annotations

import sys

from tools.comparar_com_patch import APOIO, IMAGEM, RAIZ_DO_REPOSITORIO, docker

SANITIZADORES = "-O1 -g -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"

RODADAS = {
    "compilação normal": "make -s -C /repo/verifier BUILD_DIR=/tmp/normal test",
    "com sanitizadores": f"make -s -C /repo/verifier BUILD_DIR=/tmp/sanitizado CFLAGS='{SANITIZADORES}' test",
}


def main() -> int:
    if docker("info").returncode != 0:
        raise SystemExit("Precisa do Docker rodando.")
    construcao = docker("build", "-q", "-t", IMAGEM, str(APOIO))
    if construcao.returncode != 0:
        raise SystemExit(f"não consegui montar a imagem:\n{construcao.stderr}")

    problemas = []
    for nome, comando in RODADAS.items():
        execucao = docker("run", "--rm", "-v", f"{RAIZ_DO_REPOSITORIO}:/repo:ro", IMAGEM, "sh", "-c", comando)
        print(nome)
        for linha in execucao.stdout.splitlines():
            print(f"  {linha}")
        for linha in execucao.stderr.splitlines():
            print(f"  aviso: {linha}")
        if execucao.returncode != 0:
            problemas.append(f"{nome}: saiu com {execucao.returncode}")
        elif execucao.stderr.strip():
            problemas.append(f"{nome}: escreveu na saída de erro")

    print("\ntudo certo" if not problemas else "\nHÁ PROBLEMAS\n" + "\n".join(problemas))
    return 0 if not problemas else 1


if __name__ == "__main__":
    sys.exit(main())
