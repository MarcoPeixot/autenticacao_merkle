"""Teste de mutação da suíte.

Aplica um defeito de cada vez a uma cópia do modelo de referência e roda os
testes. Uma suíte que continua passando com o modelo quebrado não está
testando aquela regra. O esperado é que todo defeito seja detectado.

Uso, a partir da raiz do repositório:

    python3 -m tools.mutacoes
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent

# nome do defeito -> (trecho original de ref/merkle.py, trecho com o defeito)
MUTACOES = {
    "folha sem a posição": (
        'return hashlib.sha256(LEAF_MAGIC + struct.pack(">I", pos) + data).digest()',
        "return hashlib.sha256(LEAF_MAGIC + data).digest()",
    ),
    "posição em little-endian": (
        'LEAF_MAGIC + struct.pack(">I", pos) + data',
        'LEAF_MAGIC + struct.pack("<I", pos) + data',
    ),
    "nó interno com filhos invertidos": (
        "return hashlib.sha256(NODE_MAGIC + left + right).digest()",
        "return hashlib.sha256(NODE_MAGIC + right + left).digest()",
    ),
    "mesmo prefixo para folha e nó": (
        'NODE_MAGIC = b"\\x02"',
        'NODE_MAGIC = b"\\x01"',
    ),
    "sem checagem de tamanho": (
        "    if len(sig) != proof_size(root.levels):\n        return ENOPKG\n",
        "    sig = sig + bytes(proof_size(root.levels))\n",
    ),
    "último nó pareado com zeros": (
        "right = prev[n + 1] if n + 1 < len(prev) else prev[n]",
        "right = prev[n + 1] if n + 1 < len(prev) else bytes(32)",
    ),
    "níveis calculados errado": (
        "return (val - 1).bit_length()",
        "return val.bit_length()",
    ),
    "percurso ignora a posição": (
        "        if pos & 1 == 0:\n"
        "            cur = node_hash(cur, hash_sigs[i])\n"
        "        else:\n"
        "            cur = node_hash(hash_sigs[i], cur)",
        "        cur = node_hash(cur, hash_sigs[i])",
    ),
}


def main() -> int:
    original = (RAIZ_DO_REPOSITORIO / "ref" / "merkle.py").read_text(encoding="utf-8")
    sobreviventes = 0

    with tempfile.TemporaryDirectory() as temporario:
        for numero, (nome, (antes, depois)) in enumerate(MUTACOES.items()):
            assert original.count(antes) == 1, f"trecho da mutação '{nome}' não encontrado uma única vez"
            copia = Path(temporario) / f"mutacao-{numero}"
            shutil.copytree(RAIZ_DO_REPOSITORIO, copia, ignore=shutil.ignore_patterns("__pycache__", ".git"))
            (copia / "ref" / "merkle.py").write_text(original.replace(antes, depois), encoding="utf-8")

            execucao = subprocess.run(
                [sys.executable, "-B", "-m", "unittest"], cwd=copia, capture_output=True, text=True
            )
            detectada = execucao.returncode != 0
            sobreviventes += 0 if detectada else 1
            resumo = execucao.stderr.strip().splitlines()[-1]
            print(f"{nome:34s} {'detectada' if detectada else 'NÃO DETECTADA'}  {resumo}")

    total = len(MUTACOES)
    print(f"\n{total - sobreviventes} de {total} defeitos detectados")
    return 1 if sobreviventes else 0


if __name__ == "__main__":
    sys.exit(main())
