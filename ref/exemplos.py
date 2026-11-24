"""Conteúdos de módulo determinísticos, usados nos testes, nos vetores e nos experimentos.

Nada aqui é aleatório: o mesmo índice gera sempre os mesmos bytes, então tudo
o que depende destes módulos é reproduzível.
"""

from __future__ import annotations

from typing import List


def modulo(i: int) -> bytes:
    """Conteúdo do módulo de índice ``i``. Cada índice tem bytes e tamanho próprios."""
    return f"modulo-{i:05d}:".encode() + bytes([(i * 37 + k) % 256 for k in range(17 + i % 23)])


def modulos(n: int, inicio: int = 0) -> List[bytes]:
    """Os módulos de índice ``inicio`` até ``inicio + n - 1``."""
    return [modulo(i) for i in range(inicio, inicio + n)]
