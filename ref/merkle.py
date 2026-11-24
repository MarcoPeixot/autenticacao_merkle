"""Modelo de referência do esquema de hashes de módulos do kernel Linux.

Reproduz, em Python, o que faz o patch
"[PATCH v5 12/14] module: Introduce hash-based integrity checking"
(Thomas Weißschuh, 5 de maio de 2026):

- a construção da árvore e das provas, de ``scripts/modules-merkle-tree.c``;
- a verificação, de ``kernel/module/hashes.c``.

Os nomes das funções são os do patch, para que a conferência possa ser feita
linha a linha. Este arquivo não tem otimização nenhuma: a função dele é ser
lido, não ser rápido.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, List, Sequence

HASH_SIZE = 32        # MODULE_HASHES_HASH_SIZE = SHA256_DIGEST_SIZE
POS_SIZE = 4          # campo ``__be32 pos`` de struct module_hashes_proof
LEAF_MAGIC = b"\x01"  # prefixo de separação de domínio da folha
NODE_MAGIC = b"\x02"  # prefixo de separação de domínio do nó interno

# Resultados de module_hash_check(). O kernel devolve 0, -ENOPKG ou -ENOKEY.
OK = "OK"
ENOPKG = "ENOPKG"     # a prova não tem o tamanho esperado
ENOKEY = "ENOKEY"     # o caminho recalculado não chega à raiz

LeafHash = Callable[[int, bytes], bytes]


def hash_data(pos: int, data: bytes) -> bytes:
    """Hash da folha: SHA-256(0x01 || pos || módulo).

    ``pos`` entra com 32 bits em big-endian (``cpu_to_be32`` no kernel,
    ``htobe32`` na ferramenta de compilação).
    """
    return hashlib.sha256(LEAF_MAGIC + struct.pack(">I", pos) + data).digest()


def hash_entry(left: bytes, right: bytes) -> bytes:
    """Hash do nó interno: SHA-256(0x02 || esquerdo || direito)."""
    return hashlib.sha256(NODE_MAGIC + left + right).digest()


def log2_roundup(val: int) -> int:
    """Número de níveis de uma árvore com ``val`` folhas.

    No patch: ``if (val <= 1) return 1; return 32 - __builtin_clz(val - 1);``
    """
    if val <= 1:
        return 1
    return (val - 1).bit_length()


@dataclass(frozen=True)
class Root:
    """``struct module_hashes_root``: número de níveis e hash da raiz."""

    levels: int
    hash: bytes


# O que write_merkle_root() grava quando não há nenhum módulo: zero níveis e
# um hash só de zeros. Nenhum módulo é aceito contra essa raiz.
EMPTY_ROOT = Root(0, bytes(HASH_SIZE))


class MerkleTree:
    """Árvore construída como em ``build_merkle()``.

    As folhas ficam na ordem recebida, que no patch é a de ``modules.order``,
    e a posição de cada módulo é o seu índice nessa lista. Quando um nível tem
    quantidade ímpar de nós, o último é pareado consigo mesmo.
    """

    def __init__(self, modules: Sequence[bytes], leaf_hash: LeafHash = hash_data):
        if not modules:
            raise ValueError("árvore sem módulos; a raiz desse caso é EMPTY_ROOT")

        self.num_files = len(modules)
        self.leaves: List[bytes] = [leaf_hash(pos, data) for pos, data in enumerate(modules)]
        self.num_levels = log2_roundup(self.num_files)

        # level_hashes[0] é o primeiro nível de pares; level_hashes[-1] é a raiz.
        self.level_hashes: List[List[bytes]] = []
        prev = self.leaves
        for _ in range(self.num_levels):
            cur = []
            for n in range(0, len(prev), 2):
                right = prev[n + 1] if n + 1 < len(prev) else prev[n]
                cur.append(hash_entry(prev[n], right))
            self.level_hashes.append(cur)
            prev = cur

        # O patch deixa um "FIXME assert single hash in root"; aqui a checagem existe.
        assert len(prev) == 1, "o último nível deveria ter um único hash"

    @property
    def root(self) -> Root:
        return Root(self.num_levels, self.level_hashes[-1][0])

    def siblings(self, n: int) -> List[bytes]:
        """Os hashes irmãos do caminho da folha ``n`` até a raiz, como em ``build_proof()``."""
        if not 0 <= n < self.num_files:
            raise IndexError(f"não existe módulo na posição {n}")

        if n & 1 == 0:
            # Sem par: a folha é o próprio irmão.
            sib = self.leaves[n] if n + 1 == self.num_files else self.leaves[n + 1]
        else:
            sib = self.leaves[n - 1]
        out = [sib]

        for i in range(self.num_levels - 1):
            n >>= 1
            level = self.level_hashes[i]
            if n & 1 == 0:
                out.append(level[n] if n + 1 == len(level) else level[n + 1])
            else:
                out.append(level[n - 1])
        return out

    def proof(self, n: int) -> bytes:
        """A prova gravada para o módulo ``n``: posição e um hash irmão por nível."""
        return make_proof(n, self.siblings(n))


def make_proof(pos: int, hash_sigs: Sequence[bytes]) -> bytes:
    """Serializa ``struct module_hashes_proof``: ``__be32 pos`` seguido dos hashes."""
    return struct.pack(">I", pos) + b"".join(hash_sigs)


def proof_size(levels: int) -> int:
    """``struct_size(proof, hash_sigs, levels)``: 4 + 32 x níveis bytes."""
    return POS_SIZE + HASH_SIZE * levels


def module_hashes_verify_proof(root: Root, pos: int, hash_sigs: Sequence[bytes], cur: bytes) -> bool:
    """Sobe o caminho: a cada nível, o bit menos significativo de ``pos``
    decide se o hash corrente entra à esquerda ou à direita."""
    for i in range(root.levels):
        if pos & 1 == 0:
            cur = hash_entry(cur, hash_sigs[i])
        else:
            cur = hash_entry(hash_sigs[i], cur)
        pos >>= 1
    return cur == root.hash


def module_hash_check(root: Root, mod: bytes, sig: bytes, leaf_hash: LeafHash = hash_data) -> str:
    """Decide se o módulo ``mod`` é aceito com a prova ``sig`` contra ``root``.

    Devolve ``OK``, ``ENOPKG`` (tamanho da prova errado) ou ``ENOKEY``
    (o caminho não chega à raiz), na mesma ordem de checagens do kernel.
    """
    if len(sig) != proof_size(root.levels):
        return ENOPKG

    (pos,) = struct.unpack(">I", sig[:POS_SIZE])
    hash_sigs = [
        sig[POS_SIZE + HASH_SIZE * i : POS_SIZE + HASH_SIZE * (i + 1)]
        for i in range(root.levels)
    ]

    modhash = leaf_hash(pos, mod)
    if not module_hashes_verify_proof(root, pos, hash_sigs, modhash):
        return ENOKEY
    return OK
