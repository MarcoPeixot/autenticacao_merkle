"""Gera os vetores de teste de raiz única.

Cada vetor traz a raiz, o módulo, a prova e a decisão esperada. A decisão é
escrita à mão em cada caso, de acordo com a regra que o caso mira; o modelo de
referência só é usado para construir as árvores e as provas. Um teste confere
depois que o modelo decide como o vetor diz.

O verificador em C vai ler este mesmo arquivo.

Uso, a partir da raiz do repositório:

    python3 -m tools.gerar_vetores            # mostra quantos vetores há
    python3 -m tools.gerar_vetores --gravar   # grava vectors/raiz-unica.json
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Dict, List

from ref.exemplos import modulo, modulos
from ref.merkle import EMPTY_ROOT, ENOKEY, ENOPKG, HASH_SIZE, OK, MerkleTree, Root, make_proof

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA = RAIZ_DO_REPOSITORIO / "vectors" / "raiz-unica.json"

TAMANHOS = (1, 2, 3, 5, 8, 13)


def inverte_bit(dados: bytes) -> bytes:
    return bytes([dados[0] ^ 0x01]) + dados[1:]


def vetores() -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []

    def caso(nome: str, mira: str, raiz: Root, mod: bytes, prova: bytes, esperado: str) -> None:
        out.append(
            {
                "name": nome,
                "targets": mira,
                "root": {"levels": raiz.levels, "hash": raiz.hash.hex()},
                "module": mod.hex(),
                "proof": prova.hex(),
                "expected": esperado,
            }
        )

    for n in TAMANHOS:
        m = modulos(n)
        arvore = MerkleTree(m)
        raiz = arvore.root
        niveis = arvore.num_levels

        for i in range(n):
            caso(f"n{n}-valido-pos{i}", "prova legítima", raiz, m[i], arvore.proof(i), OK)

        # Os casos de recusa usam o último módulo: em árvores de tamanho ímpar
        # é ele que fica pareado consigo mesmo.
        i = n - 1
        prova = arvore.proof(i)
        irmaos = arvore.siblings(i)

        caso(f"n{n}-modulo-alterado", "ligação entre módulo e folha", raiz, m[i] + b"!", prova, ENOKEY)
        caso(f"n{n}-prova-truncada", "checagem de tamanho", raiz, m[i], prova[:-HASH_SIZE], ENOPKG)
        caso(f"n{n}-prova-alongada", "checagem de tamanho", raiz, m[i], prova + bytes(HASH_SIZE), ENOPKG)
        caso(f"n{n}-prova-vazia", "checagem de tamanho", raiz, m[i], b"", ENOPKG)
        caso(
            f"n{n}-irmao-alterado",
            "caminho até a raiz",
            raiz,
            m[i],
            make_proof(i, [inverte_bit(irmaos[0])] + irmaos[1:]),
            ENOKEY,
        )
        if niveis >= 2 and irmaos[0] != irmaos[1]:
            caso(
                f"n{n}-irmaos-trocados",
                "ordem dos irmãos",
                raiz,
                m[i],
                make_proof(i, [irmaos[1], irmaos[0]] + irmaos[2:]),
                ENOKEY,
            )
        caso(
            f"n{n}-posicao-bits-altos",
            "posição: mesmo percurso, folha diferente",
            raiz,
            m[i],
            make_proof(i + 2**niveis, irmaos),
            ENOKEY,
        )
        if n < 2**niveis:
            caso(
                f"n{n}-posicao-inexistente",
                "posição: primeira posição depois do último módulo",
                raiz,
                m[i],
                make_proof(n, irmaos),
                ENOKEY,
            )
        if n >= 2:
            caso(f"n{n}-prova-de-outro-modulo", "ligação entre módulo e prova", raiz, m[0], prova, ENOKEY)
            caso(
                f"n{n}-posicao-de-outro-modulo",
                "posição: trocada por outra posição real",
                raiz,
                m[i],
                make_proof(0, irmaos),
                ENOKEY,
            )

        raiz_alheia = MerkleTree([x + b"-outra" for x in m]).root
        caso(f"n{n}-raiz-de-outra-arvore", "raiz", raiz_alheia, m[i], prova, ENOKEY)
        caso(
            f"n{n}-niveis-da-raiz-adulterados",
            "checagem de tamanho",
            Root(niveis + 1, raiz.hash),
            m[i],
            prova,
            ENOPKG,
        )

    caso("vazia-recusa-tudo", "raiz sem módulos", EMPTY_ROOT, modulo(0), struct.pack(">I", 0), ENOKEY)
    caso(
        "vazia-prova-com-irmao",
        "raiz sem módulos: checagem de tamanho",
        EMPTY_ROOT,
        modulo(0),
        MerkleTree(modulos(2)).proof(0),
        ENOPKG,
    )
    return out


def documento() -> str:
    corpo = {
        "format": 1,
        "scheme": "patch-v5-single-root",
        "description": (
            "Vetores de raiz única. Campos em hexadecimal: root.hash, module e proof. "
            "expected é OK, ENOPKG (tamanho da prova) ou ENOKEY (caminho não chega à raiz)."
        ),
        "vectors": vetores(),
    }
    return json.dumps(corpo, ensure_ascii=False, indent=1) + "\n"


def main() -> None:
    lista = vetores()
    por_decisao: Dict[str, int] = {}
    for v in lista:
        por_decisao[str(v["expected"])] = por_decisao.get(str(v["expected"]), 0) + 1
    print(f"{len(lista)} vetores: " + ", ".join(f"{k} {v}" for k, v in sorted(por_decisao.items())))
    if "--gravar" in sys.argv[1:]:
        SAIDA.write_text(documento(), encoding="utf-8")
        print(f"gravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")


if __name__ == "__main__":
    main()
