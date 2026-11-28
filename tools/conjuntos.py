"""Conjuntos de teste do benchmark: 128 a 8.192 módulos em 1, 4 e 16 raízes.

Cada conjunto é dividido em árvores de mesmo tamanho, como na tabela de
tamanhos de prova. A árvore 0 é a principal, no formato do patch, e a raiz
dela vem da configuração íntegra. As outras são complementares, no formato de
``spec/README.md``: folha com árvore, componente e geração, manifesto assinado
com ML-DSA, política e tabela de revogação.

- Cada árvore complementar ``i`` tem a autoridade ``i`` e o componente ``i``.
  A autoridade só autoriza a própria árvore e o próprio componente.
- Versão 1, geração 1 e permissão 1 em todas. A tabela de revogação inicial
  exige geração mínima 1 de cada componente, então todos os módulos passam.
- Os módulos são os de ``ref/exemplos.py``, com índice global: os mesmos bytes
  da tabela de tamanhos de prova.
- Variantes: ``padrao`` (manifesto formato 1, nó do patch) e ``enderecos``
  (formato 2, nó com árvore, nível e índice).

As chaves ML-DSA saem de sementes fixas e a assinatura é determinística, então
os arquivos gerados são sempre os mesmos. São chaves de teste, não segredo.

Uso, a partir da raiz do repositório:

    python3 -m tools.conjuntos                # tabela de tamanhos no terminal
    python3 -m tools.conjuntos --gravar       # grava bench/conjuntos.csv e docs/conjuntos.md
    python3 -m tools.conjuntos --arquivos     # grava as entradas em bench/conjuntos/ (OpenSSL >= 3.5)

A tabela não precisa de OpenSSL: as assinaturas têm tamanho fixo no FIPS 204.
Para ``--arquivos``, o ``openssl`` vem da variável ``OPENSSL``, do PATH ou do
Homebrew, nessa ordem. ``--saida``, ``--modulos``, ``--raizes``,
``--variantes`` e ``--ml-dsa`` restringem ou mudam o destino.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ref.exemplos import modulos
from ref.merkle import LeafHash, MerkleTree, Root, make_proof
from tools.medir_ml_dsa import FIPS_204
from tools.tamanhos_de_prova import CONJUNTOS, RAIZES

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA_CSV = RAIZ_DO_REPOSITORIO / "bench" / "conjuntos.csv"
SAIDA_MD = RAIZ_DO_REPOSITORIO / "docs" / "conjuntos.md"
PASTA_ARQUIVOS = RAIZ_DO_REPOSITORIO / "bench" / "conjuntos"

VARIANTES = {"padrao": 1, "enderecos": 2}  # nome -> formato do manifesto
ML_DSA = (44, 65, 87)

KERNEL = hashlib.sha256(b"kernel do benchmark").digest()
VERSAO = 1
GERACAO = 1
PERMISSOES = 1
VERSAO_DA_REVOGACAO = 1

MANIFESTO_BYTES = 98  # campos assinados do manifesto
VERSAO_BYTES = 44  # registro de versão no estado: árvore, versão e SHA-256 do manifesto


def chave_publica_bytes(conjunto: int) -> int:
    return FIPS_204[f"ML-DSA-{conjunto}"].publica


def assinatura_bytes(conjunto: int) -> int:
    return FIPS_204[f"ML-DSA-{conjunto}"].assinatura


# --- Árvores -----------------------------------------------------------------


def folha_complementar(arvore: int, componente: int, geracao: int) -> LeafHash:
    """Folha complementar: SHA-256(0x03 || árvore || posição || componente || geração || módulo)."""
    prefixo = struct.pack(">BI", 3, arvore)
    sufixo = struct.pack(">IQ", componente, geracao)

    def folha(pos: int, data: bytes) -> bytes:
        return hashlib.sha256(prefixo + struct.pack(">I", pos) + sufixo + data).digest()

    return folha


def no_com_endereco(arvore: int, nivel: int, indice: int, esquerdo: bytes, direito: bytes) -> bytes:
    """Nó da variante com endereços: SHA-256(0x04 || árvore || nível || índice || esquerdo || direito)."""
    return hashlib.sha256(struct.pack(">BIBI", 4, arvore, nivel, indice) + esquerdo + direito).digest()


class ArvoreComEnderecos:
    """Árvore complementar da variante com endereços nos nós internos.

    Mesma forma da árvore do patch: o último nó de um nível ímpar é pareado
    consigo mesmo e há pelo menos um nível. Só o hash do nó muda. A interface
    é a de ``MerkleTree``: ``root``, ``num_levels`` e ``proof``.
    """

    def __init__(self, arvore: int, folhas: Sequence[bytes]):
        if not folhas:
            raise ValueError("árvore complementar sem folhas")
        self.num_files = len(folhas)
        self.camadas: List[List[bytes]] = [list(folhas)]
        nivel = 0
        while nivel == 0 or len(self.camadas[-1]) > 1:
            atual = self.camadas[-1]
            pares = atual + [atual[-1]] if len(atual) % 2 else atual
            self.camadas.append(
                [no_com_endereco(arvore, nivel, i // 2, pares[i], pares[i + 1]) for i in range(0, len(pares), 2)]
            )
            nivel += 1
        self.num_levels = nivel

    @property
    def root(self) -> Root:
        return Root(self.num_levels, self.camadas[-1][0])

    def proof(self, n: int) -> bytes:
        if not 0 <= n < self.num_files:
            raise IndexError(f"não existe módulo na posição {n}")
        irmaos = []
        pos = n
        for camada in self.camadas[:-1]:
            irmao = pos ^ 1
            irmaos.append(camada[irmao] if irmao < len(camada) else camada[pos])
            pos >>= 1
        return make_proof(n, irmaos)


def arvore_complementar(variante: str, arvore: int, componente: int, geracao: int, mods: Sequence[bytes]):
    """A árvore complementar ``arvore`` na variante pedida."""
    folha = folha_complementar(arvore, componente, geracao)
    if variante == "padrao":
        return MerkleTree(mods, leaf_hash=folha)
    if variante == "enderecos":
        return ArvoreComEnderecos(arvore, [folha(i, m) for i, m in enumerate(mods)])
    raise ValueError(f"variante desconhecida: {variante}")


@dataclass
class Arvore:
    """Uma árvore do conjunto. ``id`` 0 é a principal."""

    id: int
    componente: int
    geracao: int
    modulos: List[bytes]
    construida: object  # MerkleTree ou ArvoreComEnderecos

    @property
    def raiz(self) -> Root:
        return self.construida.root

    def prova(self, n: int) -> bytes:
        return self.construida.proof(n)


def montar_arvores(variante: str, total: int, raizes: int) -> List[Arvore]:
    """As ``raizes`` árvores de um conjunto de ``total`` módulos."""
    por_arvore, resto = divmod(total, raizes)
    if resto:
        raise ValueError("os conjuntos foram escolhidos para dividir sem sobra")
    arvores = []
    for a in range(raizes):
        mods = modulos(por_arvore, inicio=a * por_arvore)
        if a == 0:
            arvores.append(Arvore(0, 0, 0, mods, MerkleTree(mods)))
        else:
            construida = arvore_complementar(variante, a, a, GERACAO, mods)
            arvores.append(Arvore(a, a, GERACAO, mods, construida))
    return arvores


# --- Formatos da especificação -------------------------------------------------


def corpo_manifesto(formato: int, arvore: Arvore) -> bytes:
    """Os 98 bytes assinados do manifesto de uma árvore complementar."""
    raiz = arvore.raiz
    return struct.pack(
        ">4sBIIQ32sIB32sQ",
        b"AMMF", formato, arvore.id, arvore.id, VERSAO, KERNEL,
        len(arvore.modulos), raiz.levels, raiz.hash, PERMISSOES,
    )  # fmt: skip


def politica(conjunto: int, chave_revogacao: bytes, autoridades: Dict[int, Tuple[bytes, Sequence[Tuple[int, int, int]]]]) -> bytes:
    """AMPO: autoridade -> (chave pública, [(árvore, componente, permissões)])."""
    out = b"AMPO" + bytes([1, conjunto]) + chave_revogacao + struct.pack(">I", len(autoridades))
    for autoridade in sorted(autoridades):
        chave, autorizacoes = autoridades[autoridade]
        out += struct.pack(">I", autoridade) + chave + struct.pack(">I", len(autorizacoes))
        out += b"".join(struct.pack(">IIQ", *a) for a in sorted(autorizacoes))
    return out


def corpo_revogacao(versao: int, geracoes: Dict[int, int]) -> bytes:
    """AMRV sem a assinatura: componente -> geração mínima."""
    out = struct.pack(">4sBQI", b"AMRV", 1, versao, len(geracoes))
    return out + b"".join(struct.pack(">IQ", c, geracoes[c]) for c in sorted(geracoes))


def estado(tabela: bytes, versoes: Dict[int, Tuple[int, bytes]]) -> bytes:
    """AMES: tabela aceita e, por árvore, (maior versão aceita, SHA-256 do manifesto)."""
    out = b"AMES\x01" + struct.pack(">I", len(tabela)) + tabela + struct.pack(">I", len(versoes))
    for arvore in sorted(versoes):
        versao, resumo = versoes[arvore]
        out += struct.pack(">IQ", arvore, versao) + resumo
    return out


# --- Assinatura ----------------------------------------------------------------


class SoTamanho:
    """Não assina: devolve zeros do tamanho certo. Serve só para contar bytes."""

    def __init__(self, conjunto: int):
        self.conjunto = conjunto

    def publica(self, autoridade: str) -> bytes:
        return bytes(chave_publica_bytes(self.conjunto))

    def assinar(self, autoridade: str, corpo: bytes) -> bytes:
        return corpo + bytes(assinatura_bytes(self.conjunto))


def versao_do_openssl(executavel: str) -> Optional[Tuple[int, int]]:
    """(maior, menor) de um OpenSSL, ou None se não for OpenSSL (o LibreSSL do macOS, por exemplo)."""
    try:
        texto = subprocess.run([executavel, "version"], capture_output=True, text=True).stdout
    except OSError:
        return None
    achado = re.match(r"OpenSSL (\d+)\.(\d+)", texto)
    return (int(achado.group(1)), int(achado.group(2))) if achado else None


def achar_openssl() -> Optional[str]:
    """Um ``openssl`` 3.5 ou mais novo, que é quando o ML-DSA entrou."""
    candidatos = [os.environ.get("OPENSSL"), shutil.which("openssl"),
                  "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"]
    for candidato in candidatos:
        if candidato and (versao_do_openssl(candidato) or (0, 0)) >= (3, 5):
            return candidato
    return None


class OpenSSL:
    """Assina com o ML-DSA do ``openssl``, com chave de semente fixa e assinatura determinística."""

    def __init__(self, conjunto: int, executavel: str, pasta_chaves: Path):
        self.conjunto = conjunto
        self.executavel = executavel
        self.pasta = pasta_chaves / f"ml-dsa-{conjunto}"
        self.pasta.mkdir(parents=True, exist_ok=True)
        self.publicas: Dict[str, bytes] = {}
        self.assinadas: Dict[Tuple[str, bytes], bytes] = {}

    def semente(self, autoridade: str) -> str:
        return hashlib.sha256(f"autenticacao_merkle: chave de teste do benchmark, ML-DSA-{self.conjunto}, {autoridade}".encode()).hexdigest()

    def chave(self, autoridade: str) -> Path:
        caminho = self.pasta / f"{autoridade}.pem"
        if not caminho.exists():
            subprocess.run(
                [self.executavel, "genpkey", "-algorithm", f"ML-DSA-{self.conjunto}",
                 "-pkeyopt", f"hexseed:{self.semente(autoridade)}", "-out", str(caminho)],
                check=True, capture_output=True,
            )  # fmt: skip
        return caminho

    def publica(self, autoridade: str) -> bytes:
        if autoridade not in self.publicas:
            der = subprocess.run(
                [self.executavel, "pkey", "-in", str(self.chave(autoridade)), "-pubout", "-outform", "DER"],
                check=True, capture_output=True,
            ).stdout
            self.publicas[autoridade] = der[-chave_publica_bytes(self.conjunto):]
        return self.publicas[autoridade]

    def assinar(self, autoridade: str, corpo: bytes) -> bytes:
        if (autoridade, corpo) not in self.assinadas:
            # A assinatura de uma só passada não lê da entrada padrão: precisa do arquivo.
            with tempfile.NamedTemporaryFile(dir=self.pasta, suffix=".corpo") as arquivo:
                arquivo.write(corpo)
                arquivo.flush()
                assinatura = subprocess.run(
                    [self.executavel, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.chave(autoridade)),
                     "-in", arquivo.name, "-pkeyopt", "deterministic:1"],
                    check=True, capture_output=True,
                ).stdout
            if len(assinatura) != assinatura_bytes(self.conjunto):
                raise RuntimeError(f"assinatura de {len(assinatura)} bytes, o FIPS 204 diz {assinatura_bytes(self.conjunto)}")
            self.assinadas[(autoridade, corpo)] = assinatura
        return corpo + self.assinadas[(autoridade, corpo)]


# --- Metadados de uma configuração -----------------------------------------------


@dataclass
class Metadados:
    """Tudo o que acompanha as árvores complementares de uma configuração."""

    manifestos: Dict[int, bytes]
    politica: bytes
    revogacao: bytes
    estado: bytes


def montar_metadados(variante: str, arvores: Sequence[Arvore], conjunto: int, assinador) -> Metadados:
    """Manifestos, política, tabela de revogação e o estado depois de aceitar todas as árvores.

    Com uma raiz só não há árvore complementar: os metadados ficam vazios.
    """
    complementares = [a for a in arvores if a.id != 0]
    if not complementares:
        return Metadados({}, b"", b"", b"")
    formato = VARIANTES[variante]
    corpos = {a.id: corpo_manifesto(formato, a) for a in complementares}
    manifestos = {a.id: assinador.assinar(f"autoridade-{a.id}", corpos[a.id]) for a in complementares}
    autoridades = {
        a.id: (assinador.publica(f"autoridade-{a.id}"), [(a.id, a.componente, PERMISSOES)]) for a in complementares
    }
    revogacao = assinador.assinar("revogacao", corpo_revogacao(VERSAO_DA_REVOGACAO, {a.componente: GERACAO for a in complementares}))
    versoes = {a.id: (VERSAO, hashlib.sha256(corpos[a.id]).digest()) for a in complementares}
    return Metadados(
        manifestos=manifestos,
        politica=politica(conjunto, assinador.publica("revogacao"), autoridades),
        revogacao=revogacao,
        estado=estado(revogacao, versoes),
    )


def resumo_das_raizes(arvores: Sequence[Arvore]) -> str:
    """SHA-256 de todas as raízes (níveis em u32 e hash), para conferir a regeneração."""
    return hashlib.sha256(b"".join(struct.pack(">I", a.raiz.levels) + a.raiz.hash for a in arvores)).hexdigest()


# --- Tabela de tamanhos -----------------------------------------------------------


def medir(
    variantes: Iterable[str] = VARIANTES,
    conjuntos: Iterable[int] = CONJUNTOS,
    raizes: Iterable[int] = RAIZES,
    ml_dsa: Iterable[int] = ML_DSA,
) -> List[Dict[str, object]]:
    """Uma linha por variante, conjunto, número de raízes e conjunto ML-DSA, com os tamanhos em bytes."""
    linhas = []
    for variante in variantes:
        for total in conjuntos:
            for r in raizes:
                arvores = montar_arvores(variante, total, r)
                principal = arvores[0]
                prova = len(principal.prova(0))
                for conjunto in ml_dsa:
                    meta = montar_metadados(variante, arvores, conjunto, SoTamanho(conjunto))
                    manifestos = sum(len(m) for m in meta.manifestos.values())
                    linhas.append(
                        {
                            "variante": variante,
                            "modulos": total,
                            "raizes": r,
                            "ml_dsa": conjunto,
                            "modulos_por_arvore": len(principal.modulos),
                            "niveis": principal.raiz.levels,
                            "prova_bytes": prova,
                            "provas_total_bytes": prova * total,
                            "manifesto_bytes": len(next(iter(meta.manifestos.values()), b"")),
                            "manifestos_total_bytes": manifestos,
                            "politica_bytes": len(meta.politica),
                            "revogacao_bytes": len(meta.revogacao),
                            "estado_bytes": len(meta.estado),
                            "assinaturas_por_modulo_bytes": assinatura_bytes(conjunto) * total,
                            "raizes_sha256": resumo_das_raizes(arvores),
                        }
                    )
    return linhas


def milhar(valor: int) -> str:
    return f"{valor:,}".replace(",", ".")


def decimal(valor: float) -> str:
    return f"{valor:.1f}".replace(".", ",")


def documento(linhas: List[Dict[str, object]]) -> str:
    padrao = [l for l in linhas if l["variante"] == "padrao"]
    por_raiz = {}
    for l in padrao:
        por_raiz.setdefault((l["raizes"], l["ml_dsa"]), l)

    tabela_meta = [
        "| Raízes | ML-DSA | Manifesto (cada) | Todos os manifestos | Política | Tabela de revogação | Estado |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for (r, conjunto), l in sorted(por_raiz.items()):
        if r == 1:
            continue
        tabela_meta.append(
            f"| {r} | {conjunto} | {milhar(l['manifesto_bytes'])} | {milhar(l['manifestos_total_bytes'])} "
            f"| {milhar(l['politica_bytes'])} | {milhar(l['revogacao_bytes'])} | {milhar(l['estado_bytes'])} |"
        )

    cabecalho = " | ".join(f"Com manifestos, ML-DSA-{c}" for c in ML_DSA)
    tabela_modulo = [
        f"| Módulos | Raízes | Prova | {cabecalho} |",
        "| ---: | ---: | ---: |" + " ---: |" * len(ML_DSA),
    ]
    agrupado: Dict[Tuple[int, int], Dict[int, Dict[str, object]]] = {}
    for l in padrao:
        agrupado.setdefault((l["modulos"], l["raizes"]), {})[l["ml_dsa"]] = l
    for (total, r), por_conjunto in sorted(agrupado.items()):
        prova = next(iter(por_conjunto.values()))["prova_bytes"]
        celulas = [decimal(prova + por_conjunto[c]["manifestos_total_bytes"] / total) for c in ML_DSA]
        tabela_modulo.append(f"| {milhar(total)} | {r} | {prova} | " + " | ".join(celulas) + " |")

    assinaturas = ", ".join(f"ML-DSA-{c}: {milhar(assinatura_bytes(c))}" for c in ML_DSA)
    return (
        "# Conjuntos de teste: tamanhos\n\n"
        "Gerado por `python3 -m tools.conjuntos --gravar`. Os tamanhos são os dos bytes montados no formato "
        "de `spec/README.md`, com as assinaturas do tamanho do FIPS 204. Os dados por configuração, com as duas "
        "variantes e um resumo das raízes, estão em `bench/conjuntos.csv`.\n\n"
        "Cada conjunto é dividido em árvores de mesmo tamanho. A árvore 0 é a principal, no formato do patch. "
        "As outras são complementares, cada uma com a sua autoridade, um componente e um manifesto. "
        "A variante com endereços nos nós tem os mesmos tamanhos.\n\n"
        "## Metadados das árvores complementares (bytes)\n\n"
        "Não dependem do número de módulos, só do número de raízes e do conjunto ML-DSA. "
        "Os manifestos acompanham os módulos. A política é provisionada pelo dono do sistema, e o estado fica "
        "com o verificador. Com uma raiz só, que é o caso do patch, não há nenhum deles.\n\n"
        + "\n".join(tabela_meta)
        + "\n\n"
        "## Bytes por módulo\n\n"
        "A prova de cada módulo mais a parte dele nos manifestos (todos os manifestos divididos pelo número de "
        "módulos).\n\n"
        + "\n".join(tabela_modulo)
        + "\n\n"
        f"Para comparar, uma assinatura ML-DSA por módulo (FIPS 204), em bytes: {assinaturas}.\n"
    )


def texto_csv(linhas: List[Dict[str, object]]) -> str:
    saida = io.StringIO()
    escritor = csv.DictWriter(saida, fieldnames=list(linhas[0].keys()), lineterminator="\n")
    escritor.writeheader()
    escritor.writerows(linhas)
    return saida.getvalue()


# --- Arquivos de entrada do benchmark ---------------------------------------------


def casos(arvores: Sequence[Arvore]) -> bytes:
    """Um registro por módulo: árvore, componente, geração, módulo e prova, com os tamanhos em u32."""
    out = bytearray()
    for a in arvores:
        for n, modulo in enumerate(a.modulos):
            prova = a.prova(n)
            out += struct.pack(">IIQI", a.id, a.componente, a.geracao, len(modulo)) + modulo
            out += struct.pack(">I", len(prova)) + prova
    return bytes(out)


def gravar_arquivos(
    saida: Path,
    openssl: str,
    variantes: Iterable[str] = VARIANTES,
    conjuntos: Iterable[int] = CONJUNTOS,
    raizes: Iterable[int] = RAIZES,
    ml_dsa: Iterable[int] = ML_DSA,
) -> int:
    """Grava as entradas do benchmark em ``saida/<variante>/<N>x<R>/``. Devolve quantas configurações gravou."""
    ml_dsa = list(ml_dsa)
    assinadores = {c: OpenSSL(c, openssl, saida / "chaves") for c in ml_dsa}
    gravadas = 0
    for variante in variantes:
        for total in conjuntos:
            for r in raizes:
                arvores = montar_arvores(variante, total, r)
                pasta = saida / variante / f"{total}x{r}"
                pasta.mkdir(parents=True, exist_ok=True)
                principal = arvores[0].raiz
                (pasta / "raiz.bin").write_bytes(struct.pack(">I", principal.levels) + principal.hash)
                (pasta / "kernel.bin").write_bytes(KERNEL)
                (pasta / "casos.bin").write_bytes(casos(arvores))
                for conjunto in ml_dsa:
                    meta = montar_metadados(variante, arvores, conjunto, assinadores[conjunto])
                    destino = pasta / f"ml-dsa-{conjunto}"
                    destino.mkdir(exist_ok=True)
                    if r > 1:
                        (destino / "politica.bin").write_bytes(meta.politica)
                        (destino / "revogacao.bin").write_bytes(meta.revogacao)
                        for arvore, manifesto in meta.manifestos.items():
                            (destino / f"manifesto-{arvore}.bin").write_bytes(manifesto)
                gravadas += 1
    return gravadas


# --- Linha de comando --------------------------------------------------------------


def lista_de_inteiros(texto: str) -> List[int]:
    return [int(x) for x in texto.split(",") if x]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Conjuntos de teste do benchmark.")
    parser.add_argument("--gravar", action="store_true", help="grava bench/conjuntos.csv e docs/conjuntos.md")
    parser.add_argument("--arquivos", action="store_true", help="grava as entradas do benchmark (OpenSSL >= 3.5)")
    parser.add_argument("--saida", type=Path, default=PASTA_ARQUIVOS, help="pasta das entradas")
    parser.add_argument("--modulos", type=lista_de_inteiros, default=list(CONJUNTOS))
    parser.add_argument("--raizes", type=lista_de_inteiros, default=list(RAIZES))
    parser.add_argument("--variantes", type=lambda t: t.split(","), default=list(VARIANTES))
    parser.add_argument("--ml-dsa", type=lista_de_inteiros, default=list(ML_DSA))
    args = parser.parse_args(argv)

    if args.arquivos:
        openssl = achar_openssl()
        if openssl is None:
            print("Precisa de OpenSSL 3.5 ou mais novo (variável OPENSSL, PATH ou Homebrew).", file=sys.stderr)
            return 1
        n = gravar_arquivos(args.saida, openssl, args.variantes, args.modulos, args.raizes, args.ml_dsa)
        print(f"{n} configurações gravadas em {args.saida}")
        return 0

    linhas = medir()
    texto = documento(linhas)
    print(texto)
    if args.gravar:
        SAIDA_MD.write_text(texto, encoding="utf-8")
        SAIDA_CSV.write_text(texto_csv(linhas), encoding="utf-8")
        print("gravado em docs/conjuntos.md e bench/conjuntos.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
