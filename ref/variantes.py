"""Variantes do esquema, usadas só nos testes e nos experimentos.

As enfraquecidas removem uma regra: se um ataque passa quando a regra sai e
falha quando ela volta, a regra está justificada. Uma falha que só aparece
aqui pertence à variante, não ao patch.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Callable

from .merkle import LEAF_MAGIC, LeafHash


def hash_data_sem_posicao(pos: int, data: bytes) -> bytes:
    """Folha sem a posição: SHA-256(0x01 || módulo).

    A posição continua guiando o caminho na verificação, mas deixa de fazer
    parte do que a folha autentica.
    """
    return hashlib.sha256(LEAF_MAGIC + data).digest()


def hash_data_com_arvore(arvore: int) -> LeafHash:
    """Folha com o número da árvore: SHA-256(0x01 || árvore || pos || módulo).

    Devolve a função de folha da árvore ``arvore``. O número entra com 32 bits
    em big-endian, como a posição. Os nós internos não mudam.
    """

    def folha(pos: int, data: bytes) -> bytes:
        return hashlib.sha256(LEAF_MAGIC + struct.pack(">II", arvore, pos) + data).digest()

    return folha


def truncar(digest: bytes, bits: int) -> bytes:
    """Mantém os ``bits`` primeiros bits e zera o resto, sem mudar o tamanho."""
    cheios, resto = divmod(bits, 8)
    if resto == 0:
        return digest[:cheios] + bytes(len(digest) - cheios)
    ultimo = digest[cheios] & (0xFF00 >> resto) & 0xFF
    return digest[:cheios] + bytes([ultimo]) + bytes(len(digest) - cheios - 1)


def truncado(funcao: Callable[..., bytes], bits: int) -> Callable[..., bytes]:
    """A mesma função de hash com a saída truncada a ``bits`` bits.

    Serve para experimentos de busca, que com 256 bits não terminam. Como o
    tamanho continua 32 bytes, a árvore, a prova e o verificador são os mesmos.
    """

    def com_truncamento(*argumentos) -> bytes:
        return truncar(funcao(*argumentos), bits)

    return com_truncamento
