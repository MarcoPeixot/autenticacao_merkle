"""Variantes enfraquecidas de propósito.

Cada variante remove uma regra do esquema. Se um ataque passa quando a regra
sai e falha quando ela volta, a regra está justificada. Uma falha que só
aparece aqui pertence à variante, não ao patch.
"""

from __future__ import annotations

import hashlib

from .merkle import LEAF_MAGIC


def hash_data_sem_posicao(pos: int, data: bytes) -> bytes:
    """Folha sem a posição: SHA-256(0x01 || módulo).

    A posição continua guiando o caminho na verificação, mas deixa de fazer
    parte do que a folha autentica.
    """
    return hashlib.sha256(LEAF_MAGIC + data).digest()
