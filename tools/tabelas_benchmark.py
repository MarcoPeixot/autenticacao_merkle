"""Tabelas do benchmark, montadas só a partir dos dados brutos de ``bench/dados/``.

Os dados saem de ``python3 -m tools.benchmark --gravar``. Daqui saem:

1. o tempo de cada operação por configuração (mediana e intervalo interquartil);
2. a comparação entre a variante padrão e a com endereços nos nós, no caminho
   complementar (a pergunta de ``docs/conta-multialvo.md``);
3. o tempo para verificar o conjunto inteiro, com o manifesto conferido a cada
   módulo, como a API faz hoje, e conferido uma vez por raiz;
4. a memória.

O total de um conjunto é a soma, operação por operação, de itens vezes a
mediana do tempo por item.

Uso, a partir da raiz do repositório:

    python3 -m tools.tabelas_benchmark            # tabelas no terminal
    python3 -m tools.tabelas_benchmark --gravar   # também grava docs/benchmark.md
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from tools.medir_ml_dsa import mediana_e_quartis

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
DADOS = RAIZ_DO_REPOSITORIO / "bench" / "dados"
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "benchmark.md"

OPERACOES = {
    "principal": "Raiz principal",
    "caminho_complementar": "Caminho complementar",
    "manifesto": "Manifesto",
    "complementar": "Complementar completa",
}

Configuracao = Tuple[str, int, int, int]  # variante, módulos, raízes, ML-DSA


@dataclass
class Dados:
    tempos: Dict[Tuple[Configuracao, str], List[float]] = field(default_factory=dict)
    itens: Dict[Tuple[Configuracao, str], int] = field(default_factory=dict)
    memoria: Dict[Configuracao, Tuple[int, int, int]] = field(default_factory=dict)
    ambiente: List[str] = field(default_factory=list)

    def mediana(self, config: Configuracao, operacao: str) -> Optional[float]:
        valores = self.tempos.get((config, operacao))
        return mediana_e_quartis(valores)[0] if valores else None

    def configuracoes(self, variante: str) -> List[Configuracao]:
        return sorted({c for c, _ in self.tempos if c[0] == variante}, key=lambda c: (c[1], c[2], c[3]))


def ler_dados(pasta: Path) -> Dados:
    dados = Dados()
    with (pasta / "verificador.csv").open(encoding="utf-8") as arquivo:
        for linha in csv.DictReader(arquivo):
            config = (linha["variante"], int(linha["modulos"]), int(linha["raizes"]), int(linha["ml_dsa"]))
            chave = (config, linha["operacao"])
            dados.tempos.setdefault(chave, []).append(float(linha["microssegundos"]))
            dados.itens[chave] = int(linha["itens"])
    memoria = pasta / "memoria.csv"
    if memoria.exists():
        with memoria.open(encoding="utf-8") as arquivo:
            for linha in csv.DictReader(arquivo):
                config = (linha["variante"], int(linha["modulos"]), int(linha["raizes"]), int(linha["ml_dsa"]))
                dados.memoria[config] = (int(linha["pico_bytes"]), int(linha["entradas_bytes"]), int(linha["estado_bytes"]))
    ambiente = pasta / "ambiente.txt"
    if ambiente.exists():
        dados.ambiente = [l for l in ambiente.read_text(encoding="utf-8").splitlines() if l.strip()]
    return dados


def numero(valor: float, casas: int = 2) -> str:
    texto = f"{valor:,.{casas}f}"
    return texto.replace(",", " ").replace(".", ",").replace(" ", ".")


def milhar(valor: int) -> str:
    return f"{valor:,}".replace(",", ".")


def celula(valores: Optional[List[float]]) -> str:
    if not valores:
        return "–"
    mediana, q1, q3 = mediana_e_quartis(valores)
    return f"{numero(mediana)} ({numero(q1)}–{numero(q3)})"


def ml_dsa(conjunto: int) -> str:
    return str(conjunto) if conjunto else "–"


@dataclass
class Totais:
    patch: Optional[float]  # N módulos contra uma raiz só
    api_atual: Optional[float]  # manifesto conferido a cada módulo
    manifesto_uma_vez: Optional[float]  # manifesto conferido uma vez por raiz


def totais(dados: Dados, config: Configuracao) -> Totais:
    """Tempo, em µs, para verificar todos os módulos de uma configuração."""
    variante, total, raizes, _ = config

    def custo(c: Configuracao, operacao: str) -> Optional[float]:
        mediana = dados.mediana(c, operacao)
        return None if mediana is None else mediana * dados.itens[(c, operacao)]

    unica = custo((variante, total, 1, 0), "principal")
    if raizes == 1:
        return Totais(unica, unica, unica)
    principal = custo(config, "principal")
    partes_api = [principal, custo(config, "complementar")]
    partes_uma_vez = [principal, custo(config, "caminho_complementar"), custo(config, "manifesto")]
    soma = lambda partes: None if None in partes else sum(partes)  # noqa: E731
    return Totais(unica, soma(partes_api), soma(partes_uma_vez))


def em_ms(valor: Optional[float]) -> str:
    return "–" if valor is None else numero(valor / 1000)


def tabela_tempos(dados: Dados, variante: str) -> List[str]:
    linhas = [
        "| Módulos | Raízes | ML-DSA | " + " | ".join(OPERACOES.values()) + " |",
        "| ---: | ---: | ---: |" + " ---: |" * len(OPERACOES),
    ]
    for config in dados.configuracoes(variante):
        _, total, raizes, conjunto = config
        celulas = [celula(dados.tempos.get((config, op))) for op in OPERACOES]
        linhas.append(f"| {milhar(total)} | {raizes} | {ml_dsa(conjunto)} | " + " | ".join(celulas) + " |")
    return linhas


def tabela_variantes(dados: Dados) -> List[str]:
    """O caminho não depende do ML-DSA: uma linha por conjunto e número de raízes, da rodada com o menor ML-DSA."""
    linhas = [
        "| Módulos | Raízes | Padrão (µs) | Com endereços (µs) | Com endereços / padrão |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    vistos = set()
    for config in dados.configuracoes("padrao"):
        _, total, raizes, conjunto = config
        if raizes == 1 or (total, raizes) in vistos:
            continue
        padrao = dados.mediana(config, "caminho_complementar")
        enderecos = dados.mediana(("enderecos", total, raizes, conjunto), "caminho_complementar")
        if padrao is None or enderecos is None:
            continue
        vistos.add((total, raizes))
        linhas.append(
            f"| {milhar(total)} | {raizes} | {numero(padrao)} | {numero(enderecos)} | {numero(enderecos / padrao)} |"
        )
    return linhas


def tabela_totais(dados: Dados, variante: str) -> List[str]:
    linhas = [
        "| Módulos | Raízes | ML-DSA | Uma raiz, como o patch (ms) | Manifesto a cada módulo (ms) | Manifesto uma vez por raiz (ms) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for config in dados.configuracoes(variante):
        _, total, raizes, conjunto = config
        if raizes == 1:
            continue
        t = totais(dados, config)
        linhas.append(
            f"| {milhar(total)} | {raizes} | {ml_dsa(conjunto)} | {em_ms(t.patch)} | {em_ms(t.api_atual)} "
            f"| {em_ms(t.manifesto_uma_vez)} |"
        )
    return linhas


def tabela_memoria(dados: Dados, variante: str) -> List[str]:
    linhas = [
        "| Módulos | Raízes | ML-DSA | Pico do processo (KiB) | Entradas lidas (KiB) | Estado (bytes) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for config in sorted((c for c in dados.memoria if c[0] == variante), key=lambda c: (c[1], c[2], c[3])):
        _, total, raizes, conjunto = config
        pico, entradas, estado = dados.memoria[config]
        linhas.append(
            f"| {milhar(total)} | {raizes} | {ml_dsa(conjunto)} | {milhar(pico // 1024)} | {milhar(entradas // 1024)} "
            f"| {milhar(estado)} |"
        )
    return linhas


def documento(dados: Dados) -> str:
    partes = [
        "# Benchmark do verificador em C",
        "",
        "Gerado por `python3 -m tools.tabelas_benchmark --gravar`, só a partir dos dados brutos de `bench/dados/`, "
        "que saem de `python3 -m tools.benchmark --gravar`. O método está em `bench/README.md`.",
        "",
        "Os tempos são por item, em µs: mediana das rodadas e, entre parênteses, o primeiro e o terceiro quartil. "
        "Os módulos são pequenos (dezenas de bytes), então o tempo é o do esquema, não o do hash do arquivo.",
        "",
        "## Ambiente",
        "",
        *(dados.ambiente or ["- não registrado"]),
        "",
        "## Tempo por operação, variante padrão (µs)",
        "",
        "Raiz principal e caminho complementar são por módulo, manifesto é por árvore complementar e a verificação "
        "complementar completa (regras R2 a R8) é por módulo, com a conferência do manifesto dentro.",
        "",
        *tabela_tempos(dados, "padrao"),
        "",
        "## Padrão × endereços nos nós: caminho complementar (µs por módulo)",
        "",
        *tabela_variantes(dados),
        "",
        "## Tempo para verificar o conjunto inteiro, variante padrão (ms)",
        "",
        "Soma, operação por operação, de itens vezes a mediana do tempo por item. A verificação complementar da API "
        "atual confere o manifesto a cada módulo. Na última coluna o manifesto é conferido uma vez por raiz e cada "
        "módulo só sobe o caminho.",
        "",
        *tabela_totais(dados, "padrao"),
        "",
        "## Memória, variante padrão",
        "",
        "Pico de memória residente do processo do medidor, com as entradas carregadas, e tamanho do estado depois "
        "de aceitar todas as árvores.",
        "",
        *tabela_memoria(dados, "padrao"),
        "",
        "## Variante com endereços: tempo por operação (µs)",
        "",
        *tabela_tempos(dados, "enderecos"),
    ]
    return "\n".join(partes) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Tabelas do benchmark a partir dos dados brutos.")
    parser.add_argument("--dados", type=Path, default=DADOS, help="pasta dos dados brutos")
    parser.add_argument("--gravar", action="store_true", help="grava docs/benchmark.md")
    parser.add_argument("--saida", type=Path, default=SAIDA, help="arquivo das tabelas")
    args = parser.parse_args(argv)

    if not (args.dados / "verificador.csv").exists():
        print(f"Sem dados brutos em {args.dados}. Rode: python3 -m tools.benchmark --gravar", file=sys.stderr)
        return 1
    texto = documento(ler_dados(args.dados))
    print(texto)
    if args.gravar:
        args.saida.write_text(texto, encoding="utf-8")
        print(f"gravado em {args.saida}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
