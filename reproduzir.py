"""Roda tudo de uma vez: testes, teste de mutação, experimento da posição,
tabela de tamanhos e vetores de teste.

    python3 reproduzir.py

Os arquivos gerados em docs/, bench/ e vectors/ são regravados. Como nada é
aleatório, eles têm de sair iguais aos que já estão no repositório.
"""

import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent

PASSOS = [
    ("testes", ["-m", "unittest"]),
    ("teste de mutação", ["-m", "tools.mutacoes"]),
    ("experimento da posição", ["-m", "tools.experimento_posicao", "--gravar"]),
    ("tabela de tamanhos", ["-m", "tools.tamanhos_de_prova", "--gravar"]),
    ("vetores de teste", ["-m", "tools.gerar_vetores", "--gravar"]),
]


def main() -> int:
    if sys.version_info < (3, 9):
        print("Precisa de Python 3.9 ou mais novo.")
        return 1

    inicio = time.perf_counter()
    for nome, argumentos in PASSOS:
        comeco = time.perf_counter()
        execucao = subprocess.run([sys.executable, "-B", *argumentos], cwd=RAIZ, capture_output=True, text=True)
        duracao = time.perf_counter() - comeco
        if execucao.returncode != 0:
            print(f"FALHOU  {nome}\n")
            print(execucao.stdout)
            print(execucao.stderr)
            return 1
        saida = (execucao.stdout.strip() or execucao.stderr.strip()).splitlines()
        print(f"ok      {nome:24s} {duracao:5.1f}s   {saida[-1] if saida else ''}")

    print(f"\ntudo certo em {time.perf_counter() - inicio:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
