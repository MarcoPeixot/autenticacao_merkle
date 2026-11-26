"""Compara o modelo em Python com o código do próprio patch, num container Linux.

São duas comparações:

1. A ferramenta de compilação (``patch-v5/scripts/modules-merkle-tree.c``)
   gera a raiz e as provas das mesmas árvores que o modelo constrói. O arquivo
   da raiz e cada arquivo de prova têm de sair iguais, byte a byte.
2. O verificador do kernel (``patch-v5/kernel/module/hashes.c``) decide os
   vetores de ``vectors/raiz-unica.json`` e todas as provas que a ferramenta
   gerou. A decisão tem de ser a esperada e a mesma do modelo.

Os arquivos de ``patch-v5/`` são os do patch, sem alteração. Antes de rodar, o
script confere o hash de blob de cada um com o índice do próprio diff.

Precisa de Docker. Uso, a partir da raiz do repositório:

    python3 -m tools.comparar_com_patch            # resultado no terminal
    python3 -m tools.comparar_com_patch --gravar   # também grava em docs/
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from ref.exemplos import modulo
from ref.merkle import EMPTY_ROOT, HASH_SIZE, OK, MerkleTree, Root, module_hash_check

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
PATCH = RAIZ_DO_REPOSITORIO / "patch-v5"
APOIO = RAIZ_DO_REPOSITORIO / "tools" / "patch_no_linux"
VETORES = RAIZ_DO_REPOSITORIO / "vectors" / "raiz-unica.json"
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "comparacao-com-patch.md"
IMAGEM = "autenticacao-merkle-patch:trixie"

# arquivo -> (início do hash de blob esperado, de onde vem o valor)
ORIGEM: Dict[str, Tuple[str, str]] = {
    "scripts/modules-merkle-tree.c": ("10e3455d5d7a", "índice do diff (arquivo novo)"),
    "kernel/module/hashes.c": ("3d3cf0366f75", "índice do diff (arquivo novo)"),
    "include/linux/module_hashes.h": ("53b34fa12f2d", "índice do diff (arquivo novo)"),
    "scripts/include/xalloc.h": ("8294bc0b836f", "índice do diff (depois do patch)"),
    "tools/include/uapi/linux/module_signature.h": ("78e206996eed", "índice do diff (depois do patch)"),
    "scripts/ssl-common.h": ("2db0e181143c", "Linux 4dce97c6c265 (o patch não mexe)"),
}

# Árvores de 0 a 64 módulos, as bordas das potências de 2 e o kernel do Debian 13.
TAMANHOS = list(range(0, 65)) + [100, 127, 128, 129, 1000, 1023, 1024, 1025, 4096, 4230, 8192]

# Rodapé que a ferramenta grava depois da prova: struct module_signature
# (id_type = MODULE_SIGNATURE_TYPE_MERKLE, sig_len = tamanho da prova) e o marcador.
MARCADOR = b"~Module signature appended~\n"
TIPO_MERKLE = 3


def blob(caminho: Path) -> str:
    """Hash de blob do git, o mesmo que aparece nas linhas ``index`` de um diff."""
    dados = caminho.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(dados) + dados).hexdigest()


def conferir_origem() -> List[Tuple[str, str, str, bool]]:
    """(arquivo, hash calculado, de onde vem o esperado, confere?) para cada arquivo de patch-v5/."""
    linhas = []
    for nome, (esperado, origem) in ORIGEM.items():
        calculado = blob(PATCH / nome)[:12]
        linhas.append((nome, calculado, origem, calculado == esperado))
    return linhas


def raiz_em_c(raiz: Root) -> str:
    """O arquivo que ``write_merkle_root()`` grava para esta raiz."""
    texto = "#include <linux/module_hashes.h>\n\n"
    texto += "const struct\n"
    texto += "module_hashes_root module_hashes_root __module_hashes_section = {\n"
    texto += f"\t.levels = {raiz.levels},\n"
    texto += "\t.hash = {{"
    for i, byte in enumerate(raiz.hash):
        if i % 8 == 0:
            texto += "\n\t\t"
        texto += f"0x{byte:02x}," + (" " if (i + 1) % 8 else "")
    texto += "\n\t}},"
    texto += "\n};\n"
    return texto


def arquivo_de_prova(prova: bytes) -> bytes:
    """O arquivo ``.merkle`` que a ferramenta grava para esta prova."""
    rodape = struct.pack(">BBBBB3xI", 0, 0, TIPO_MERKLE, 0, 0, len(prova))
    return prova + rodape + MARCADOR


def prova_do_arquivo(dados: bytes) -> bytes:
    """Separa a prova do rodapé, como o kernel faz antes de chamar o verificador."""
    if not dados.endswith(MARCADOR) or len(dados) < 12 + len(MARCADOR):
        raise ValueError("arquivo de prova sem o marcador no fim")
    rodape = dados[-len(MARCADOR) - 12 : -len(MARCADOR)]
    (tamanho,) = struct.unpack(">I", rodape[8:])
    return dados[:tamanho]


def ler_raiz_em_c(texto: str) -> Root:
    """Lê níveis e hash de um arquivo gravado por ``write_merkle_root()``."""
    niveis = int(texto.split(".levels = ")[1].split(",")[0])
    bytes_hex = texto.split(".hash = {{")[1].split("}}")[0]
    valores = [int(v, 16) for v in bytes_hex.replace(",", " ").split()]
    if len(valores) != HASH_SIZE:
        raise ValueError("raiz sem 32 bytes")
    return Root(niveis, bytes(valores))


@dataclass
class Resultado:
    origem: List[Tuple[str, str, str, bool]]
    ambiente: List[str] = field(default_factory=list)
    avisos_ferramenta: str = ""
    avisos_verificador: str = ""
    arvores: int = 0
    raizes_iguais: int = 0
    modulos: int = 0
    provas_iguais: int = 0
    vetores: Counter = field(default_factory=Counter)  # esperado -> quantos
    vetores_iguais_ao_esperado: Counter = field(default_factory=Counter)
    vetores_iguais_ao_modelo: int = 0
    provas_da_ferramenta_aceitas: int = 0
    diferencas: List[str] = field(default_factory=list)

    @property
    def tudo_igual(self) -> bool:
        return (
            all(ok for *_, ok in self.origem)
            and self.raizes_iguais == self.arvores
            and self.provas_iguais == self.modulos
            and sum(self.vetores_iguais_ao_esperado.values()) == sum(self.vetores.values())
            and self.vetores_iguais_ao_modelo == sum(self.vetores.values())
            and self.provas_da_ferramenta_aceitas == self.modulos
        )


def docker(*argumentos: str, entrada: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *argumentos], input=entrada, capture_output=True, text=True)


def rodar_no_container(trabalho: Path, etapa: str) -> None:
    execucao = docker(
        "run", "--rm",
        "-v", f"{PATCH}:/fonte/patch:ro",
        "-v", f"{APOIO}:/fonte/apoio:ro",
        "-v", f"{trabalho}:/trabalho",
        IMAGEM, "sh", "/fonte/apoio/rodar.sh", etapa,
    )  # fmt: skip
    if execucao.returncode != 0:
        raise SystemExit(f"falhou no container ({etapa}):\n{execucao.stdout}{execucao.stderr}")


def comparar() -> Resultado:
    res = Resultado(origem=conferir_origem())
    if not all(ok for *_, ok in res.origem):
        return res

    if docker("info").returncode != 0:
        raise SystemExit("Precisa do Docker rodando.")
    construcao = docker("build", "-q", "-t", IMAGEM, str(APOIO))
    if construcao.returncode != 0:
        raise SystemExit(f"não consegui montar a imagem:\n{construcao.stderr}")

    with tempfile.TemporaryDirectory() as temporario:
        trabalho = Path(temporario).resolve()
        arvores: Dict[int, Path] = {}
        for n in TAMANHOS:
            pasta = trabalho / "arvores" / f"{n:05d}"
            pasta.mkdir(parents=True)
            (pasta / "modules.order").write_text("".join(f"m{i:05d}.o\n" for i in range(n)))
            for i in range(n):
                (pasta / f"m{i:05d}.ko").write_bytes(modulo(i))
            arvores[n] = pasta

        # 1. ferramenta de compilação
        rodar_no_container(trabalho, "ferramenta")
        saida = trabalho / "saida"
        res.ambiente = (saida / "ambiente.txt").read_text().splitlines()
        res.avisos_ferramenta = (saida / "avisos-ferramenta.txt").read_text().strip()

        casos: List[str] = []
        decisoes_esperadas: List[str] = []
        for n, pasta in arvores.items():
            res.arvores += 1
            if n == 0:
                raiz = EMPTY_ROOT
                arvore = None
            else:
                arvore = MerkleTree([modulo(i) for i in range(n)])
                raiz = arvore.root
            texto = (pasta / "raiz.c").read_text()
            if texto == raiz_em_c(raiz):
                res.raizes_iguais += 1
            else:
                res.diferencas.append(f"raiz da árvore de {n} módulos")
            raiz_da_ferramenta = ler_raiz_em_c(texto)

            for i in range(n):
                res.modulos += 1
                dados = (pasta / f"m{i:05d}.merkle").read_bytes()
                if dados == arquivo_de_prova(arvore.proof(i)):
                    res.provas_iguais += 1
                else:
                    res.diferencas.append(f"prova do módulo {i} na árvore de {n}")
                # o verificador do kernel recebe a prova da ferramenta contra a raiz da ferramenta
                casos.append(
                    f"{raiz_da_ferramenta.levels} {raiz_da_ferramenta.hash.hex()} "
                    f"{modulo(i).hex()} {prova_do_arquivo(dados).hex()}"
                )
                decisoes_esperadas.append("ferramenta")

        # 2. verificador do kernel
        vetores = json.loads(VETORES.read_text(encoding="utf-8"))["vectors"]
        for v in vetores:
            casos.append(
                f"{v['root']['levels']} {v['root']['hash']} {v['module'] or '-'} {v['proof'] or '-'}"
            )
            decisoes_esperadas.append("vetor")
        (trabalho / "casos.txt").write_text("\n".join(casos) + "\n")

        rodar_no_container(trabalho, "verificador")
        res.avisos_verificador = (saida / "avisos-verificador.txt").read_text().strip()
        respostas = (saida / "respostas.txt").read_text().split()
        assert len(respostas) == len(casos), "o verificador não respondeu todos os casos"

        n_ferramenta = decisoes_esperadas.count("ferramenta")
        res.provas_da_ferramenta_aceitas = respostas[:n_ferramenta].count("OK")
        for v, resposta in zip(vetores, respostas[n_ferramenta:]):
            esperado = v["expected"]
            modelo = module_hash_check(
                Root(v["root"]["levels"], bytes.fromhex(v["root"]["hash"])),
                bytes.fromhex(v["module"]),
                bytes.fromhex(v["proof"]),
            )
            res.vetores[esperado] += 1
            if resposta == esperado:
                res.vetores_iguais_ao_esperado[esperado] += 1
            else:
                res.diferencas.append(f"vetor {v['name']}: kernel {resposta}, esperado {esperado}")
            if resposta == modelo:
                res.vetores_iguais_ao_modelo += 1
    return res


def avisos(texto: str) -> str:
    """Resume a saída do compilador: uma linha por aviso, sem o caminho do container."""
    itens = []
    for linha in texto.splitlines():
        if ": warning: " in linha:
            local, mensagem = linha.split(": warning: ", 1)
            local = local.replace("/fonte/patch/", "patch-v5/").replace("/fonte/apoio/", "tools/patch_no_linux/")
            itens.append(f"`{local}`: {mensagem}")
    if not texto:
        return "nenhum"
    return "; ".join(itens) if itens else "ver a saída do compilador"


def numero(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def relatorio(res: Resultado) -> str:
    linhas = ["## Arquivos do patch", ""]
    linhas += [
        "| Arquivo | Hash de blob | Conferido com | Confere |",
        "| -------------------------------------------- | -------------- | ------------------------------------ | -------- |",
    ]
    for nome, calculado, origem, ok in res.origem:
        linhas.append(f"| `{nome}` | `{calculado}` | {origem} | {'sim' if ok else '**não**'} |")
    if not all(ok for *_, ok in res.origem):
        linhas += ["", "Algum arquivo de `patch-v5/` não é o do patch. A comparação não rodou."]
        return "\n".join(linhas)

    linhas += ["", "## Ambiente", ""]
    linhas += [f"- {l}" for l in res.ambiente]
    linhas += [
        f"- avisos ao compilar a ferramenta com `-Wall -Wextra`: {avisos(res.avisos_ferramenta)}",
        f"- avisos ao compilar o verificador com `-Wall -Wextra`: {avisos(res.avisos_verificador)}",
    ]

    linhas += ["", "## Ferramenta de compilação", ""]
    linhas += [
        f"Árvores de {', '.join(map(str, TAMANHOS[:3]))} … {TAMANHOS[64]} módulos e de "
        f"{', '.join(numero(n) for n in TAMANHOS[65:])} módulos.",
        "",
        "| | Iguais ao modelo | Total |",
        "| --- | ---: | ---: |",
        f"| Arquivos de raiz (`raiz.c`) | {numero(res.raizes_iguais)} | {numero(res.arvores)} |",
        f"| Arquivos de prova (`.merkle`) | {numero(res.provas_iguais)} | {numero(res.modulos)} |",
    ]

    linhas += ["", "## Verificador do kernel", ""]
    total = sum(res.vetores.values())
    linhas += [
        "| Casos | Decisão esperada | Total | Kernel decidiu igual |",
        "| --- | --- | ---: | ---: |",
        f"| Provas geradas pela ferramenta | OK | {numero(res.modulos)} | {numero(res.provas_da_ferramenta_aceitas)} |",
    ]
    for esperado in ("OK", "ENOPKG", "ENOKEY"):
        linhas.append(
            f"| Vetores de `raiz-unica.json` | {esperado} | {res.vetores[esperado]} | "
            f"{res.vetores_iguais_ao_esperado[esperado]} |"
        )
    linhas += ["", f"Nos {total} vetores, o kernel e o modelo deram a mesma decisão em {res.vetores_iguais_ao_modelo}."]

    if res.diferencas:
        linhas += ["", f"## Diferenças ({numero(len(res.diferencas))})", ""]
        linhas += [f"- {d}" for d in res.diferencas[:10]]
        if len(res.diferencas) > 10:
            linhas.append(f"- e mais {numero(len(res.diferencas) - 10)}")
    return "\n".join(linhas)


def main() -> int:
    res = comparar()
    texto = relatorio(res)
    print(texto)
    if "--gravar" in sys.argv[1:]:
        cabecalho = (
            "# Comparação com o código do patch: resultado bruto\n\n"
            "Gerado por `python3 -m tools.comparar_com_patch --gravar` (precisa de Docker). "
            "A leitura do resultado está no `README.md`.\n\n"
        )
        SAIDA.write_text(cabecalho + texto + "\n", encoding="utf-8")
        print(f"\ngravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")
    print("\ntudo igual" if res.tudo_igual else "\nHÁ DIFERENÇAS")
    return 0 if res.tudo_igual else 1


if __name__ == "__main__":
    sys.exit(main())
