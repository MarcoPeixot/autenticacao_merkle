"""Benchmark do verificador em C nos conjuntos de teste.

Para cada variante (padrão e com endereços), conjunto de 128 a 8.192 módulos,
número de raízes (1, 4 e 16) e conjunto ML-DSA (44, 65 e 87):

1. gera as entradas com ``tools/conjuntos.py`` (chaves de semente fixa e
   assinatura determinística, então são sempre as mesmas);
2. compila ``bench/medir.c`` junto com o verificador de ``verifier/``, uma vez
   por variante;
3. roda o medidor, que confere que todo caso é aceito antes de medir e então
   mede quatro operações: a raiz principal, o caminho complementar, a
   conferência do manifesto e a verificação complementar completa.

Com uma raiz só não há árvore complementar nem ML-DSA: a configuração roda uma
vez e fica com ``ml_dsa`` 0.

O padrão é rodar no Debian 13 do Docker, o mesmo da comparação com o patch e da
medição do ML-DSA. O repositório entra só para leitura e tudo é gerado no
/tmp do container. ``--local`` roda na própria máquina, com o OpenSSL 3.5 ou
mais novo que achar (variável ``OPENSSL``, PATH ou Homebrew); serve para
desenvolver, não para os números do artigo.

Uso, a partir da raiz do repositório:

    python3 -m tools.benchmark                         # resumo no terminal
    python3 -m tools.benchmark --gravar                # também grava os dados brutos em bench/dados/
    python3 -m tools.benchmark --local --rodadas 3 --modulos 128

As tabelas saem dos dados brutos: ``python3 -m tools.tabelas_benchmark``.
"""

from __future__ import annotations

import argparse
import csv
import platform
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from tools import conjuntos
from tools.comparar_com_patch import APOIO, IMAGEM, docker

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
MEDIDOR = RAIZ_DO_REPOSITORIO / "bench" / "medir.c"
VERIFICADOR = RAIZ_DO_REPOSITORIO / "verifier"
FONTES = ("merkle.c", "mrauth.c", "formatos.c", "arquivos.c")
DADOS = RAIZ_DO_REPOSITORIO / "bench" / "dados"
TRABALHO_LOCAL = RAIZ_DO_REPOSITORIO / "bench" / "build"
RODADAS = 30

OPERACOES = ("principal", "caminho_complementar", "manifesto", "complementar")

Configuracao = Tuple[str, int, int, int]  # variante, módulos, raízes, conjunto ML-DSA (0: sem complementar)


def configuracoes(
    variantes: Iterable[str], modulos: Iterable[int], raizes: Iterable[int], ml_dsa: Iterable[int]
) -> List[Configuracao]:
    ml_dsa = list(ml_dsa)
    saida = []
    for variante in variantes:
        for total in modulos:
            for r in raizes:
                for conjunto in ml_dsa if r > 1 else [0]:
                    saida.append((variante, total, r, conjunto))
    return saida


def esperado(config: Configuracao) -> Dict[str, int]:
    """Quantos itens cada operação verifica numa configuração."""
    _, total, raizes, _ = config
    por_arvore = total // raizes
    if raizes == 1:
        return {"principal": total}
    complementares = total - por_arvore
    return {
        "principal": por_arvore,
        "caminho_complementar": complementares,
        "manifesto": raizes - 1,
        "complementar": complementares,
    }


@dataclass
class Medicao:
    ambiente: List[str] = field(default_factory=list)
    casos: Dict[Tuple[Configuracao, str], Tuple[int, int]] = field(default_factory=dict)  # (itens, repetições)
    tempos: Dict[Tuple[Configuracao, str], List[float]] = field(default_factory=dict)  # µs por item
    memoria: Dict[Configuracao, Tuple[int, int, int]] = field(default_factory=dict)  # pico, entradas, estado

    def configuracoes(self) -> List[Configuracao]:
        vistas = []
        for config, _ in self.tempos:
            if config not in vistas:
                vistas.append(config)
        return vistas

    def problemas(self, rodadas: int, esperadas: Sequence[Configuracao]) -> List[str]:
        """O que falta ou não bate. Vazio quando está tudo certo."""
        saida = []
        for config in esperadas:
            nome = " ".join(map(str, config))
            if config not in self.memoria:
                saida.append(f"{nome}: sem medição de memória")
            for operacao, itens in esperado(config).items():
                casos = self.casos.get((config, operacao))
                if casos is None or casos[0] != itens:
                    saida.append(f"{nome}, {operacao}: {casos[0] if casos else 'nenhum'} itens, esperado {itens}")
                if len(self.tempos.get((config, operacao), [])) != rodadas:
                    saida.append(f"{nome}, {operacao}: não tem {rodadas} rodadas")
        return saida


def ler_saida(texto: str) -> Medicao:
    """Lê a saída de ``executar``: linhas de ambiente e, por configuração, o que ``medir.c`` imprime."""
    med = Medicao()
    config: Optional[Configuracao] = None
    for linha in texto.splitlines():
        if not linha.strip():
            continue
        tipo, _, resto = linha.partition(" ")
        campos = resto.split()
        if tipo == "ambiente":
            med.ambiente.append(resto)
        elif tipo == "config":
            config = (campos[0], int(campos[1]), int(campos[2]), int(campos[3]))
        elif config is None:
            raise ValueError(f"linha antes de qualquer configuração: {linha!r}")
        elif tipo == "casos":
            med.casos[(config, campos[0])] = (int(campos[1]), int(campos[2]))
        elif tipo == "tempo":
            med.tempos[(config, campos[0])] = [float(v) for v in campos[1:]]
        elif tipo == "memoria":
            med.memoria[config] = (int(campos[0]), int(campos[1]), int(campos[2]))
        else:
            raise ValueError(f"linha que não reconheço: {linha!r}")
    return med


# --- Execução: a mesma no host (--local) e dentro do container ---------------------


def flags_do_openssl(openssl: str) -> Tuple[List[str], List[str]]:
    """Flags de compilação e de ligação da libcrypto: pelo pkg-config ou ao lado do executável."""
    if shutil.which("pkg-config"):
        cflags = subprocess.run(["pkg-config", "--cflags", "libcrypto"], capture_output=True, text=True)
        libs = subprocess.run(["pkg-config", "--libs", "libcrypto"], capture_output=True, text=True)
        if cflags.returncode == 0 and libs.returncode == 0:
            return cflags.stdout.split(), libs.stdout.split()
    prefixo = Path(openssl).resolve().parent.parent
    if (prefixo / "include" / "openssl" / "evp.h").exists():
        return [f"-I{prefixo / 'include'}"], [f"-L{prefixo / 'lib'}", "-lcrypto"]
    return [], ["-lcrypto"]


def compilar(destino: Path, openssl: str, variantes: Iterable[str]) -> Tuple[Dict[str, Path], List[str]]:
    """Compila o medidor uma vez por variante. Devolve os executáveis e os avisos do compilador."""
    destino.mkdir(parents=True, exist_ok=True)
    cflags, libs = flags_do_openssl(openssl)
    fontes = [str(MEDIDOR)] + [str(VERIFICADOR / f) for f in FONTES]
    executaveis, avisos = {}, []
    for variante in variantes:
        saida = destino / f"medir-{variante}"
        definicoes = ["-DMERKLE_ENDERECOS"] if variante == "enderecos" else []
        comando = ["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", f"-I{VERIFICADOR}",
                   *cflags, *definicoes, *fontes, *libs, "-o", str(saida)]  # fmt: skip
        execucao = subprocess.run(comando, capture_output=True, text=True)
        if execucao.returncode != 0:
            raise SystemExit(f"não compilou o medidor ({variante}):\n{execucao.stderr}")
        avisos += [l for l in execucao.stderr.splitlines() if l.strip()]
        executaveis[variante] = saida
    return executaveis, avisos


def primeira_linha(comando: Sequence[str]) -> str:
    try:
        execucao = subprocess.run(list(comando), capture_output=True, text=True)
    except OSError:
        return "não encontrado"
    return (execucao.stdout or execucao.stderr).strip().splitlines()[0] if (execucao.stdout or execucao.stderr).strip() else "?"


def sistema() -> str:
    os_release = Path("/etc/os-release")
    if os_release.exists():
        for linha in os_release.read_text().splitlines():
            if linha.startswith("PRETTY_NAME="):
                return linha.split("=", 1)[1].strip('"')
    return platform.platform()


def executar(
    trabalho: Path, openssl: str, rodadas: int, variantes: Sequence[str], modulos: Sequence[int],
    raizes: Sequence[int], ml_dsa: Sequence[int],
) -> str:
    """Gera os conjuntos, compila e mede. Devolve o texto que ``ler_saida`` lê."""
    linhas = [
        f"ambiente arquitetura: {platform.machine()}",
        f"ambiente compilador: {primeira_linha(['cc', '--version'])}",
        f"ambiente openssl: {primeira_linha([openssl, 'version'])}",
        f"ambiente sistema: {sistema()}",
        f"ambiente rodadas: {rodadas}",
    ]
    pasta = trabalho / "conjuntos"
    conjuntos.gravar_arquivos(pasta, openssl, variantes, modulos, raizes, ml_dsa)
    executaveis, avisos = compilar(trabalho / "build", openssl, variantes)
    linhas.append(f"ambiente avisos ao compilar: {'; '.join(avisos) or 'nenhum'}")

    for config in configuracoes(variantes, modulos, raizes, ml_dsa):
        variante, total, r, conjunto = config
        argumentos = [str(executaveis[variante]), str(pasta / variante / f"{total}x{r}"),
                      str(conjunto or ml_dsa[0]), str(rodadas)]  # fmt: skip
        execucao = subprocess.run(argumentos, capture_output=True, text=True)
        if execucao.returncode != 0:
            raise SystemExit(f"o medidor falhou em {' '.join(map(str, config))}:\n{execucao.stderr}")
        linhas.append("config " + " ".join(map(str, config)))
        linhas += execucao.stdout.splitlines()
    return "\n".join(linhas) + "\n"


def rodar_no_docker(rodadas: int, variantes, modulos, raizes, ml_dsa) -> str:
    if docker("info").returncode != 0:
        raise SystemExit("Precisa do Docker rodando (ou use --local).")
    construcao = docker("build", "-q", "-t", IMAGEM, str(APOIO))
    if construcao.returncode != 0:
        raise SystemExit(f"não consegui montar a imagem:\n{construcao.stderr}")
    comando = (
        "cd /repo && python3 -B -m tools.benchmark --local --bruto --trabalho /tmp/bench "
        f"--rodadas {rodadas} --variantes {','.join(variantes)} --modulos {','.join(map(str, modulos))} "
        f"--raizes {','.join(map(str, raizes))} --ml-dsa {','.join(map(str, ml_dsa))}"
    )
    execucao = docker("run", "--rm", "-v", f"{RAIZ_DO_REPOSITORIO}:/repo:ro", IMAGEM, "sh", "-c", comando)
    if execucao.returncode != 0:
        raise SystemExit(f"falhou no container:\n{execucao.stdout}{execucao.stderr}")
    return execucao.stdout


# --- Dados brutos -------------------------------------------------------------------


def gravar_dados(med: Medicao, pasta: Path, maquina: str) -> None:
    pasta.mkdir(parents=True, exist_ok=True)
    with (pasta / "verificador.csv").open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow(["variante", "modulos", "raizes", "ml_dsa", "operacao", "itens", "repeticoes", "rodada", "microssegundos"])
        for (config, operacao), valores in med.tempos.items():
            itens, repeticoes = med.casos[(config, operacao)]
            for rodada, valor in enumerate(valores, start=1):
                escritor.writerow([*config, operacao, itens, repeticoes, rodada, f"{valor:.4f}"])
    with (pasta / "memoria.csv").open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow(["variante", "modulos", "raizes", "ml_dsa", "pico_bytes", "entradas_bytes", "estado_bytes"])
        for config, valores in med.memoria.items():
            escritor.writerow([*config, *valores])
    linhas = [f"- {item}" for item in med.ambiente] + [f"- máquina: {maquina}"]
    (pasta / "ambiente.txt").write_text("\n".join(linhas) + "\n", encoding="utf-8")


def maquina_local() -> str:
    if platform.system() == "Darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout
        return f"{cpu.strip()}, macOS {platform.mac_ver()[0]}"
    return f"{platform.machine()}, {platform.system()}"


def resumo(med: Medicao) -> str:
    linhas = []
    for config in med.configuracoes():
        variante, total, r, conjunto = config
        nome = f"{variante:9s} {total:5d} módulos, {r:2d} raízes" + (f", ML-DSA-{conjunto}" if conjunto else "")
        partes = []
        for operacao in OPERACOES:
            valores = med.tempos.get((config, operacao))
            if valores:
                partes.append(f"{operacao} {statistics.median(valores):.2f} µs")
        linhas.append(f"{nome}: " + ", ".join(partes))
    return "\n".join(linhas)


def lista_de_inteiros(texto: str) -> List[int]:
    return [int(x) for x in texto.split(",") if x]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark do verificador em C.")
    parser.add_argument("--local", action="store_true", help="roda nesta máquina, sem Docker")
    parser.add_argument("--bruto", action="store_true", help="só imprime a saída bruta (usado dentro do container)")
    parser.add_argument("--gravar", action="store_true", help="grava os dados brutos")
    parser.add_argument("--dados", type=Path, default=DADOS, help="pasta dos dados brutos")
    parser.add_argument("--trabalho", type=Path, default=TRABALHO_LOCAL, help="pasta para conjuntos e executáveis")
    parser.add_argument("--rodadas", type=int, default=RODADAS)
    parser.add_argument("--variantes", type=lambda t: t.split(","), default=list(conjuntos.VARIANTES))
    parser.add_argument("--modulos", type=lista_de_inteiros, default=list(conjuntos.CONJUNTOS))
    parser.add_argument("--raizes", type=lista_de_inteiros, default=list(conjuntos.RAIZES))
    parser.add_argument("--ml-dsa", type=lista_de_inteiros, default=list(conjuntos.ML_DSA))
    args = parser.parse_args(argv)
    escolha = (args.variantes, args.modulos, args.raizes, args.ml_dsa)

    if args.local:
        openssl = conjuntos.achar_openssl()
        if openssl is None:
            raise SystemExit("Precisa de OpenSSL 3.5 ou mais novo (variável OPENSSL, PATH ou Homebrew).")
        texto = executar(args.trabalho, openssl, args.rodadas, *escolha)
        if args.bruto:
            sys.stdout.write(texto)
            return 0
        maquina = maquina_local()
    else:
        from tools.medir_ml_dsa import maquina as maquina_docker

        texto = rodar_no_docker(args.rodadas, *escolha)
        maquina = maquina_docker()

    med = ler_saida(texto)
    print("\n".join(med.ambiente))
    print(resumo(med))
    problemas = med.problemas(args.rodadas, configuracoes(*escolha))
    if args.gravar:
        gravar_dados(med, args.dados, maquina)
        print(f"\ndados brutos gravados em {args.dados}")
    print("\ntudo certo" if not problemas else "\nHÁ PROBLEMAS\n" + "\n".join(problemas))
    return 0 if not problemas else 1


if __name__ == "__main__":
    sys.exit(main())
