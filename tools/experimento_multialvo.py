"""Experimento da hipótese multi-alvo.

O nó interno do patch não leva nível, índice nem identificador de árvore. A
hipótese é que, por isso, cada hash que o atacante calcula vale contra todos
os nós internos de todas as árvores ao mesmo tempo.

Com o SHA-256 inteiro a busca não termina, então os hashes são truncados a
``BITS`` bits. O atacante quer ver aceito um módulo que não está em árvore
nenhuma:

1. calcula a folha desse módulo, declarando a posição 0 da árvore 0;
2. a cada tentativa inventa um irmão e calcula o nó de cima;
3. compara o resultado com todos os nós internos de todas as árvores;
4. quando coincide, monta a prova com os irmãos legítimos dali para cima e
   entrega ao verificador.

Só conta como ataque a prova que o verificador aceita. Várias raízes aqui são
árvores com o mesmo formato de folha, e a prova vale contra a raiz que ela
indicar. Manifesto e política ficam de fora: eles não mudam nenhum hash.

Com poucos bits, uma prova errada às vezes fecha assim mesmo: o caminho que o
verificador recalcula sai de outra folha e esbarra no caminho certo mais acima.
Essas aceitas são contadas à parte ("por acaso"). Conferir uma prova são hashes
novos, cada um com um alvo só, então elas não dizem nada sobre multi-alvo.

Uso, a partir da raiz do repositório:

    python3 -m tools.experimento_multialvo            # tabela no terminal
    python3 -m tools.experimento_multialvo --gravar   # também grava em docs/
"""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Set, Tuple

from ref.exemplos import modulos
from ref.merkle import (
    ENOKEY,
    ENOPKG,
    HASH_SIZE,
    OK,
    LeafHash,
    MerkleTree,
    hash_data,
    hash_entry,
    make_proof,
    module_hash_check,
)
from ref.variantes import hash_data_com_arvore, hash_data_sem_posicao, truncado

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "experimento-multialvo.md"

BITS = 14
MODULOS_POR_ARVORE = 64
ARVORES = (1, 4, 16)
TENTATIVAS = 2 ** 20
MALICIOSO = b"modulo que nao esta em arvore nenhuma"

# nome do esquema -> função que devolve o hash de folha da árvore de número ``arvore``
ESQUEMAS: Dict[str, Callable[[int], LeafHash]] = {
    "patch": lambda arvore: hash_data,
    "folha sem posição": lambda arvore: hash_data_sem_posicao,
    "folha com árvore": hash_data_com_arvore,
}


@dataclass
class Contagem:
    arvores: int
    nos_comparados: int
    coincidencias: int = 0
    recusadas_tamanho: int = 0  # ENOPKG: o nó está em outro nível e a prova fica curta
    recusadas_caminho: int = 0  # ENOKEY: a folha recalculada pelo verificador é outra
    aceitas: int = 0            # a prova fecha passando pelo nó encontrado
    aceitas_por_acaso: int = 0  # a prova fecha por outra coincidência, mais acima
    onde: Set[Tuple[int, int, int]] = field(default_factory=set)  # (árvore, nível, índice) das aceitas


def atacar(
    folha_de: Callable[[int], LeafHash],
    bits: int = BITS,
    arvores: Sequence[int] = ARVORES,
    por_arvore: int = MODULOS_POR_ARVORE,
    tentativas: int = TENTATIVAS,
    altura: int = 1,
) -> List[Contagem]:
    """Roda a busca uma vez e devolve uma contagem para cada quantidade de árvores.

    ``altura`` é quantos níveis o atacante constrói por conta própria acima da
    folha falsa. Os irmãos dos níveis de baixo são fixos; o do último varia.
    """
    no = truncado(hash_entry, bits)
    folhas = [truncado(folha_de(a), bits) for a in range(max(arvores))]
    floresta = [
        MerkleTree(modulos(por_arvore, inicio=a * por_arvore), folhas[a], no) for a in range(max(arvores))
    ]

    # Todo nó interno de toda árvore é um alvo: hash -> [(árvore, nível, índice)].
    alvos = defaultdict(list)
    for a, arvore in enumerate(floresta):
        for nivel, hashes in enumerate(arvore.level_hashes, start=1):
            for indice, h in enumerate(hashes):
                alvos[h].append((a, nivel, indice))

    nos_por_arvore = sum(len(hashes) for hashes in floresta[0].level_hashes)
    contagens = [Contagem(r, r * nos_por_arvore) for r in arvores]

    # A folha falsa sobe pela esquerda, primeiro com os irmãos fixos.
    folha_falsa = folhas[0](0, MALICIOSO)
    cur = folha_falsa
    fixos = [bytes([k + 1]) * HASH_SIZE for k in range(altura - 1)]
    for irmao in fixos:
        cur = no(cur, irmao)

    for tentativa in range(tentativas):
        irmao = tentativa.to_bytes(HASH_SIZE, "big")
        achados = alvos.get(no(cur, irmao))
        if not achados:
            continue
        for a, nivel, indice in achados:
            arvore = floresta[a]
            pos = indice << nivel
            acima = arvore.siblings(pos)[nivel:]
            prova = make_proof(pos, fixos + [irmao] + acima)
            resposta = module_hash_check(arvore.root, MALICIOSO, prova, folhas[a], no)
            # O verificador recalcula a folha com a posição e a árvore da prova.
            # Se ela é a mesma do atacante, o caminho passa pelo nó encontrado.
            pelo_no = folhas[a](pos, MALICIOSO) == folha_falsa
            for c in contagens:
                if a >= c.arvores:
                    continue
                c.coincidencias += 1
                if resposta == OK and pelo_no:
                    c.aceitas += 1
                    c.onde.add((a, nivel, indice))
                elif resposta == OK:
                    c.aceitas_por_acaso += 1
                elif resposta == ENOPKG:
                    c.recusadas_tamanho += 1
                else:
                    assert resposta == ENOKEY
                    c.recusadas_caminho += 1
    return contagens


CABECALHO = [
    "| Esquema | Árvores | Nós comparados | Coincidências | Recusadas pelo tamanho | Recusadas pelo caminho | Aceitas | Ganho | Aceitas por acaso |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
]


def linhas(nome: str, altura: int = 1) -> List[str]:
    """Uma linha de tabela para cada quantidade de árvores."""
    um_alvo = TENTATIVAS / 2 ** BITS
    saida = []
    for c in atacar(ESQUEMAS[nome], altura=altura):
        assert c.coincidencias == c.recusadas_tamanho + c.recusadas_caminho + c.aceitas + c.aceitas_por_acaso
        # A prova só fecha pelo nó encontrado no nível que o atacante construiu.
        # Fora do esquema sem posição, só no índice 0; com a árvore na folha, só
        # na árvore 0. Se o truncamento criar outro caso, a leitura da tabela
        # muda e isto avisa.
        assert all(nivel == altura for _, nivel, _ in c.onde), c.onde
        if nome != "folha sem posição":
            assert all(indice == 0 for _, _, indice in c.onde), c.onde
        if nome == "folha com árvore":
            assert all(a == 0 for a, _, _ in c.onde), c.onde
        ganho = f"{c.aceitas / um_alvo:.1f}".replace(".", ",")
        rotulo = nome if altura == 1 else f"{nome}, altura {altura}"
        saida.append(
            f"| {rotulo} | {c.arvores} | {c.nos_comparados} | {c.coincidencias} | {c.recusadas_tamanho} | "
            f"{c.recusadas_caminho} | {c.aceitas} | {ganho} | {c.aceitas_por_acaso} |"
        )
    return saida


def tabela() -> str:
    corpo = list(CABECALHO)
    for nome in ESQUEMAS:
        corpo += linhas(nome)
    return "\n".join(corpo)


def tabela_alturas() -> str:
    """O mesmo ataque no esquema do patch, com o atacante construindo 2 e 3 níveis."""
    corpo = list(CABECALHO)
    for altura in (2, 3):
        corpo += linhas("patch", altura)
    return "\n".join(corpo)


def main() -> None:
    texto = tabela() + "\n\nSubárvore falsa mais alta, só no esquema do patch:\n\n" + tabela_alturas()
    print(texto)
    if "--gravar" in sys.argv[1:]:
        cabecalho = (
            "# Experimento multi-alvo: resultado bruto\n\n"
            "Gerado por `python3 -m tools.experimento_multialvo --gravar`. "
            "A leitura do resultado está em `docs/hipoteses.md`.\n\n"
            f"Hash truncado a {BITS} bits, {MODULOS_POR_ARVORE} módulos por árvore, "
            f"{TENTATIVAS} tentativas por esquema. Com um alvo só, o esperado é "
            f"{TENTATIVAS // 2 ** BITS} provas aceitas. O ganho é quantas vezes as aceitas passam disso. "
            "As aceitas por acaso fecham por outra coincidência no caminho e não entram no ganho.\n\n"
        )
        SAIDA.write_text(cabecalho + texto + "\n", encoding="utf-8")
        print(f"\ngravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")


if __name__ == "__main__":
    main()
