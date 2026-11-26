"""Mede o ML-DSA do OpenSSL no mesmo Debian 13 da comparação com o patch.

Para ML-DSA-44, 65 e 87, o programa ``tools/ml_dsa/medir.c``:

1. gera um par de chaves e confere os tamanhos com o FIPS 204;
2. confere que a assinatura válida passa e que mensagem alterada, assinatura
   alterada, assinatura cortada e chave de outro par não passam;
3. mede o tempo de gerar a chave, assinar e verificar.

A verificação usa só a chave pública, importada dos bytes, como o verificador
vai receber da política. A mensagem tem 128 bytes, a ordem de grandeza de um
manifesto (que ainda não tem formato).

O tempo sai de ``RODADAS`` rodadas. Cada rodada cronometra um lote de
operações e divide pelo tamanho do lote. A tabela mostra a mediana e o
intervalo interquartil das rodadas.

Precisa de Docker. Uso, a partir da raiz do repositório:

    python3 -m tools.medir_ml_dsa            # resultado no terminal
    python3 -m tools.medir_ml_dsa --gravar   # também grava em docs/
"""

from __future__ import annotations

import platform
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Sequence, Tuple

from tools.comparar_com_patch import APOIO, IMAGEM, docker

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
PROGRAMA = RAIZ_DO_REPOSITORIO / "tools" / "ml_dsa"
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "ml-dsa.md"
RODADAS = 30


class Tamanhos(NamedTuple):
    categoria: int  # categoria de segurança do NIST
    publica: int
    privada: int
    assinatura: int


# FIPS 204, tabelas 1 e 2. Tamanhos em bytes.
FIPS_204: Dict[str, Tamanhos] = {
    "ML-DSA-44": Tamanhos(2, 1312, 2560, 2420),
    "ML-DSA-65": Tamanhos(3, 1952, 4032, 3309),
    "ML-DSA-87": Tamanhos(5, 2592, 4896, 4627),
}

# caso -> (como aparece na tabela, resposta esperada)
CHECAGENS: Dict[str, Tuple[str, str]] = {
    "valida": ("Assinatura válida", "aceita"),
    "mensagem_alterada": ("Mensagem com um bit trocado", "recusa"),
    "assinatura_alterada": ("Assinatura com um bit trocado", "recusa"),
    "assinatura_cortada": ("Assinatura sem o último byte", "recusa"),
    "outra_chave": ("Chave pública de outro par", "recusa"),
}

OPERACOES = {"gerar": "Gerar a chave", "assinar": "Assinar", "verificar": "Verificar"}


@dataclass
class Medicao:
    ambiente: List[str] = field(default_factory=list)
    avisos: List[str] = field(default_factory=list)
    tamanhos: Dict[str, Tuple[int, int, int]] = field(default_factory=dict)  # (pública, privada, assinatura)
    checagens: Dict[Tuple[str, str], str] = field(default_factory=dict)  # (conjunto, caso) -> resposta
    tempos: Dict[Tuple[str, str], List[float]] = field(default_factory=dict)  # (conjunto, operação) -> µs
    maquina: str = ""

    def problemas(self, rodadas: int = RODADAS) -> List[str]:
        """O que não saiu como o FIPS 204 e as checagens mandam. Vazio quando está tudo certo."""
        saida = []
        for conjunto, fips in FIPS_204.items():
            medido = self.tamanhos.get(conjunto)
            if medido is None:
                saida.append(f"{conjunto}: não mediu")
                continue
            if medido != (fips.publica, fips.privada, fips.assinatura):
                saida.append(f"{conjunto}: tamanhos {medido}, o FIPS 204 diz {fips[1:]}")
            for caso, (rotulo, esperado) in CHECAGENS.items():
                resposta = self.checagens.get((conjunto, caso))
                if resposta != esperado:
                    saida.append(f"{conjunto}, {rotulo.lower()}: {resposta or 'sem resposta'}, esperado {esperado}")
            for operacao in OPERACOES:
                if len(self.tempos.get((conjunto, operacao), [])) != rodadas:
                    saida.append(f"{conjunto}, {operacao}: não tem {rodadas} rodadas")
        return saida


def ler_saida(texto: str) -> Medicao:
    """Lê o que ``rodar.sh`` e ``medir.c`` imprimem."""
    med = Medicao()
    for linha in texto.splitlines():
        if not linha.strip():
            continue
        tipo, _, resto = linha.partition(" ")
        campos = resto.split()
        if tipo == "ambiente":
            med.ambiente.append(resto)
        elif tipo == "aviso":
            med.avisos.append(resto)
        elif tipo == "tamanho":
            med.tamanhos[campos[0]] = (int(campos[1]), int(campos[2]), int(campos[3]))
        elif tipo == "checagem":
            med.checagens[(campos[0], campos[1])] = campos[2]
        elif tipo == "tempo":
            med.tempos[(campos[0], campos[1])] = [float(v) for v in campos[2:]]
        else:
            raise ValueError(f"linha que não reconheço: {linha!r}")
    return med


def mediana_e_quartis(valores: Sequence[float]) -> Tuple[float, float, float]:
    """(mediana, primeiro quartil, terceiro quartil)."""
    if len(valores) == 1:
        return valores[0], valores[0], valores[0]
    q1, q2, q3 = statistics.quantiles(valores, n=4, method="inclusive")
    return q2, q1, q3


def maquina() -> str:
    """Processador do computador que roda o Docker e o que o Docker tem disponível."""
    if platform.system() == "Darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout
        processador = f"{cpu.strip()}, macOS"
    else:
        processador = f"{platform.machine()}, {platform.system()}"
    info = docker("info", "--format", "{{.OperatingSystem}}, {{.NCPU}} CPUs").stdout.strip()
    return f"{processador}; {info}"


def medir(rodadas: int = RODADAS) -> Medicao:
    if docker("info").returncode != 0:
        raise SystemExit("Precisa do Docker rodando.")
    construcao = docker("build", "-q", "-t", IMAGEM, str(APOIO))
    if construcao.returncode != 0:
        raise SystemExit(f"não consegui montar a imagem:\n{construcao.stderr}")
    execucao = docker(
        "run", "--rm",
        "-v", f"{PROGRAMA}:/fonte/ml_dsa:ro",
        IMAGEM, "sh", "/fonte/ml_dsa/rodar.sh", str(rodadas),
    )  # fmt: skip
    if execucao.returncode != 0:
        raise SystemExit(f"falhou no container:\n{execucao.stdout}{execucao.stderr}")
    med = ler_saida(execucao.stdout)
    med.maquina = maquina()
    return med


def decimal(x: float) -> str:
    return f"{x:,.1f}".replace(",", " ").replace(".", ",").replace(" ", ".")


def milhar(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def relatorio(med: Medicao, rodadas: int = RODADAS) -> str:
    linhas = ["## Ambiente", ""]
    linhas += [f"- {item}" for item in med.ambiente]
    if med.maquina:
        linhas.append(f"- máquina: {med.maquina}")
    linhas.append(f"- avisos ao compilar `medir.c` com `-Wall -Wextra`: {'; '.join(med.avisos) or 'nenhum'}")

    linhas += ["", "## Tamanhos (bytes)", ""]
    linhas += [
        "| Conjunto | Categoria do NIST | Chave pública | Chave privada | Assinatura | Igual ao FIPS 204 |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for conjunto, fips in FIPS_204.items():
        medido = med.tamanhos.get(conjunto)
        if medido is None:
            linhas.append(f"| {conjunto} | {fips.categoria} | – | – | – | **não mediu** |")
            continue
        igual = medido == (fips.publica, fips.privada, fips.assinatura)
        linhas.append(
            f"| {conjunto} | {fips.categoria} | {milhar(medido[0])} | {milhar(medido[1])} | "
            f"{milhar(medido[2])} | {'sim' if igual else '**não**'} |"
        )

    linhas += ["", "## Checagens", ""]
    linhas += [
        "| Caso | Esperado | " + " | ".join(FIPS_204) + " |",
        "| --- | --- |" + " --- |" * len(FIPS_204),
    ]
    for caso, (rotulo, esperado) in CHECAGENS.items():
        respostas = []
        for conjunto in FIPS_204:
            resposta = med.checagens.get((conjunto, caso), "–")
            respostas.append(resposta if resposta == esperado else f"**{resposta}**")
        linhas.append(f"| {rotulo} | {esperado} | " + " | ".join(respostas) + " |")

    linhas += ["", "## Tempo por operação (µs)", ""]
    linhas += [
        f"Mediana das {rodadas} rodadas e, entre parênteses, o primeiro e o terceiro quartil.",
        "",
        "| Conjunto | " + " | ".join(OPERACOES.values()) + " |",
        "| --- |" + " ---: |" * len(OPERACOES),
    ]
    for conjunto in FIPS_204:
        celulas = []
        for operacao in OPERACOES:
            valores = med.tempos.get((conjunto, operacao))
            if not valores:
                celulas.append("–")
                continue
            mediana, q1, q3 = mediana_e_quartis(valores)
            celulas.append(f"{decimal(mediana)} ({decimal(q1)}–{decimal(q3)})")
        linhas.append(f"| {conjunto} | " + " | ".join(celulas) + " |")

    problemas = med.problemas(rodadas)
    if problemas:
        linhas += ["", "## Problemas", ""]
        linhas += [f"- {p}" for p in problemas]
    return "\n".join(linhas)


def main() -> int:
    med = medir()
    texto = relatorio(med)
    print(texto)
    if "--gravar" in sys.argv[1:]:
        cabecalho = (
            "# ML-DSA no ambiente: resultado bruto\n\n"
            "Gerado por `python3 -m tools.medir_ml_dsa --gravar` (precisa de Docker). "
            "A leitura do resultado está no `README.md`. Tamanhos e checagens saem sempre iguais; "
            "os tempos mudam um pouco a cada execução e dependem da máquina.\n\n"
            "Mensagem de 128 bytes. A verificação usa só a chave pública, importada dos bytes. "
            "Cada rodada cronometra um lote (50 chaves, 100 assinaturas, 200 verificações) e divide "
            "pelo tamanho do lote; antes das rodadas há uma de aquecimento, fora da conta.\n\n"
        )
        SAIDA.write_text(cabecalho + texto + "\n", encoding="utf-8")
        print(f"\ngravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")
    problemas = med.problemas()
    print("\ntudo certo" if not problemas else "\nHÁ PROBLEMAS")
    return 0 if not problemas else 1


if __name__ == "__main__":
    sys.exit(main())
