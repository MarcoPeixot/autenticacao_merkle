"""Tabela de tamanhos de prova.

Para cada conjunto de módulos, dividido em árvores de mesmo tamanho, constrói
as árvores, gera a prova de todos os módulos e mede o tamanho em bytes. Nada é
calculado por fórmula: o número vem do comprimento das provas geradas.

A comparação é com o tamanho de uma assinatura ML-DSA por módulo, nos três
conjuntos de parâmetros do FIPS 204.

Uso, a partir da raiz do repositório:

    python3 -m tools.tamanhos_de_prova            # tabela no terminal
    python3 -m tools.tamanhos_de_prova --gravar   # também grava em docs/ e bench/
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Dict, List

from ref.exemplos import modulos
from ref.merkle import HASH_SIZE, MerkleTree

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA_MD = RAIZ_DO_REPOSITORIO / "docs" / "tamanhos-de-prova.md"
SAIDA_CSV = RAIZ_DO_REPOSITORIO / "bench" / "tamanhos-de-prova.csv"

CONJUNTOS = (128, 1024, 4096, 8192)
RAIZES = (1, 4, 16)

# Tamanho da assinatura em bytes, FIPS 204.
ML_DSA = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}

# struct module_hashes_root: u32 levels + hash de 32 bytes.
BYTES_POR_RAIZ = 4 + HASH_SIZE


def medir() -> List[Dict[str, int]]:
    linhas = []
    for total in CONJUNTOS:
        for raizes in RAIZES:
            por_arvore, resto = divmod(total, raizes)
            assert resto == 0, "os conjuntos foram escolhidos para dividir sem sobra"

            tamanhos = set()
            niveis = set()
            for a in range(raizes):
                arvore = MerkleTree(modulos(por_arvore, inicio=a * por_arvore))
                niveis.add(arvore.num_levels)
                tamanhos.update(len(arvore.proof(i)) for i in range(por_arvore))
            assert len(tamanhos) == 1 and len(niveis) == 1, "toda prova de uma árvore tem o mesmo tamanho"

            prova = tamanhos.pop()
            linhas.append(
                {
                    "modulos": total,
                    "raizes": raizes,
                    "modulos_por_arvore": por_arvore,
                    "niveis": niveis.pop(),
                    "prova_bytes": prova,
                    "provas_total_bytes": prova * total,
                    "raizes_total_bytes": BYTES_POR_RAIZ * raizes,
                }
            )
    return linhas


def milhar(valor: int) -> str:
    return f"{valor:,}".replace(",", ".")


def vezes(valor: float) -> str:
    return f"{valor:.1f}".replace(".", ",")


def tabela_md(linhas: List[Dict[str, int]]) -> str:
    menor, maior = min(ML_DSA.values()), max(ML_DSA.values())
    out = [
        "| Módulos | Raízes | Módulos por árvore | Níveis | Prova por módulo (bytes) | Todas as provas (bytes) | Todas as raízes (bytes) | Assinatura ML-DSA é maior em |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for l in linhas:
        out.append(
            f"| {milhar(l['modulos'])} | {l['raizes']} | {milhar(l['modulos_por_arvore'])} | {l['niveis']} "
            f"| {l['prova_bytes']} | {milhar(l['provas_total_bytes'])} | {l['raizes_total_bytes']} "
            f"| {vezes(menor / l['prova_bytes'])} a {vezes(maior / l['prova_bytes'])} vezes |"
        )
    return "\n".join(out)


def documento(linhas: List[Dict[str, int]]) -> str:
    assinaturas = ", ".join(f"{nome}: {milhar(tam)}" for nome, tam in ML_DSA.items())
    return (
        "# Tamanhos de prova\n\n"
        "Gerado por `python3 -m tools.tamanhos_de_prova --gravar`. Os tamanhos são medidos nas provas "
        "geradas pelo modelo.\n\n"
        + tabela_md(linhas)
        + "\n\n"
        "A prova tem 4 bytes de posição e 32 por nível. Com mais árvores cada uma fica mais baixa e a "
        "prova encurta.\n\n"
        f"Assinaturas ML-DSA para comparar (FIPS 204), em bytes: {assinaturas}.\n\n"
        "Não entra na conta: o manifesto assinado de cada raiz complementar (ainda sem formato) e o "
        "rodapé de assinatura que o kernel anexa a todo módulo.\n"
    )


def gravar_csv(linhas: List[Dict[str, int]]) -> None:
    campos = list(linhas[0].keys()) + [f"assinatura_{nome.lower().replace('-', '_')}_bytes" for nome in ML_DSA]
    with SAIDA_CSV.open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=campos)
        escritor.writeheader()
        for l in linhas:
            linha = dict(l)
            for nome, tam in ML_DSA.items():
                linha[f"assinatura_{nome.lower().replace('-', '_')}_bytes"] = tam
            escritor.writerow(linha)


def main() -> None:
    linhas = medir()
    print(tabela_md(linhas))
    if "--gravar" in sys.argv[1:]:
        SAIDA_MD.write_text(documento(linhas), encoding="utf-8")
        gravar_csv(linhas)
        print("\ngravado em docs/ e bench/")


if __name__ == "__main__":
    main()
