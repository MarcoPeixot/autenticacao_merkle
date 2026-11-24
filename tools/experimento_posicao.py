"""Experimento da hipótese do uso indevido da posição.

Para uma árvore de ``n`` módulos, tenta todas as combinações de

    módulo legítimo  x  posição declarada  x  lista de irmãos de uma prova legítima

e conta quantas o verificador aceita. Só uma combinação por módulo deveria
passar: a posição verdadeira com os irmãos da própria prova. As posições
testadas vão de 0 a 2^(níveis+1) - 1, o que cobre as posições reais, as que
sobram quando a árvore não é completa e as que diferem da real só no primeiro
bit acima do percurso.

O atacante deste experimento só reaproveita dados legítimos. Ele não procura
colisões nem pré-imagens: isso é assunto da hipótese multi-alvo.

Uso, a partir da raiz do repositório:

    python3 -m tools.experimento_posicao            # tabela no terminal
    python3 -m tools.experimento_posicao --gravar   # também grava em docs/
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

from ref.exemplos import modulo
from ref.merkle import OK, LeafHash, MerkleTree, hash_data, make_proof, module_hash_check
from ref.variantes import hash_data_sem_posicao

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "experimento-posicao.md"
MAIOR_ARVORE = 32


@dataclass
class Resultado:
    n: int
    niveis: int
    testadas: int = 0
    legitimas_aceitas: int = 0
    legitimas_recusadas: int = 0
    indevidas_aceitas: int = 0
    exemplos: List[Tuple[int, int, int]] = field(default_factory=list)  # (módulo, posição, prova)


def varrer(n: int, leaf_hash: LeafHash = hash_data) -> Resultado:
    """Testa todas as combinações para uma árvore de ``n`` módulos."""
    modulos = [modulo(i) for i in range(n)]
    arvore = MerkleTree(modulos, leaf_hash=leaf_hash)
    raiz = arvore.root
    irmaos = [arvore.siblings(i) for i in range(n)]
    res = Resultado(n=n, niveis=arvore.num_levels)

    for i in range(n):
        for pos in range(2 ** (arvore.num_levels + 1)):
            for j in range(n):
                aceita = module_hash_check(raiz, modulos[i], make_proof(pos, irmaos[j]), leaf_hash) == OK
                legitima = pos == i and irmaos[j] == irmaos[i]
                res.testadas += 1
                if legitima and aceita:
                    res.legitimas_aceitas += 1
                elif legitima:
                    res.legitimas_recusadas += 1
                elif aceita:
                    res.indevidas_aceitas += 1
                    if len(res.exemplos) < 3:
                        res.exemplos.append((i, pos, j))
    return res


def tabela() -> str:
    linhas = [
        "| Módulos | Níveis | Combinações testadas | Aceitas indevidamente, esquema do patch | Aceitas indevidamente, folha sem posição |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    total = [0, 0, 0]
    for n in range(1, MAIOR_ARVORE + 1):
        patch = varrer(n)
        fraca = varrer(n, hash_data_sem_posicao)
        assert patch.legitimas_recusadas == 0 and fraca.legitimas_recusadas == 0
        assert patch.legitimas_aceitas == n and fraca.legitimas_aceitas == n
        linhas.append(
            f"| {n} | {patch.niveis} | {patch.testadas} | {patch.indevidas_aceitas} | {fraca.indevidas_aceitas} |"
        )
        total[0] += patch.testadas
        total[1] += patch.indevidas_aceitas
        total[2] += fraca.indevidas_aceitas
    linhas.append(f"| **Total** | | **{total[0]}** | **{total[1]}** | **{total[2]}** |")
    return "\n".join(linhas)


def main() -> None:
    texto = tabela()
    print(texto)
    if "--gravar" in sys.argv[1:]:
        cabecalho = (
            "# Experimento da posição: resultado bruto\n\n"
            "Gerado por `python3 -m tools.experimento_posicao --gravar`. "
            "A leitura do resultado está em `docs/hipoteses.md`.\n\n"
        )
        SAIDA.write_text(cabecalho + texto + "\n", encoding="utf-8")
        print(f"\ngravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")


if __name__ == "__main__":
    main()
