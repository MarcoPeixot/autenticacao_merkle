import json
import subprocess
import sys
from pathlib import Path

from ref.merkle import Root, module_hash_check

VETORES = Path(__file__).resolve().parent.parent / "vectors" / "raiz-unica.json"


def comparar(executavel: str) -> None:
    vetores = json.loads(VETORES.read_text(encoding="utf-8"))["vectors"]
    entrada = "".join(
        f"{v['root']['levels']} {v['root']['hash']} {v['module'] or '-'} {v['proof'] or '-'}\n"
        for v in vetores
    )
    execucao = subprocess.run(
        [executavel], input=entrada, stdout=subprocess.PIPE, text=True, check=True
    )
    respostas = execucao.stdout.splitlines()
    if len(respostas) != len(vetores):
        raise SystemExit(f"O C devolveu {len(respostas)} respostas para {len(vetores)} vetores.")

    for vetor, resposta in zip(vetores, respostas):
        raiz = Root(vetor["root"]["levels"], bytes.fromhex(vetor["root"]["hash"]))
        modelo = module_hash_check(
            raiz, bytes.fromhex(vetor["module"]), bytes.fromhex(vetor["proof"])
        )
        esperado = vetor["expected"]
        if resposta != modelo or resposta != esperado:
            raise SystemExit(f"{vetor['name']}: C={resposta}, Python={modelo}, esperado={esperado}")

    print(f"{len(vetores)} vetores com a mesma decisão no C e no Python.")


if __name__ == "__main__":
    comparar(sys.argv[1])
