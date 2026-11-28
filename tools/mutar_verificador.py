"""Teste de mutação do verificador em C, regra por regra.

Cada mutação tira uma checagem do verificador numa cópia do repositório e roda
``make -C verifier test`` no mesmo Debian 13 da comparação com o patch. A
mutação é acusada quando algum caso muda de resultado. Se ela sobrevive,
nenhum teste depende daquela checagem, ou outra checagem já cobre o caso.

Cada mutação diz a regra da especificação (``spec/README.md``) e a violação do
modelo de ameaças (``docs/modelo-de-ameacas.md``) que a checagem ajuda a barrar.
Acusada quer dizer que algum teste percebe a falta da checagem, não que o
ataque passaria: às vezes outra checagem recusa com outro motivo.

Precisa de Docker. Uso, a partir da raiz do repositório:

    python3 -m tools.mutar_verificador            # resultado no terminal
    python3 -m tools.mutar_verificador --gravar   # também grava em docs/
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, NamedTuple, Optional, Sequence, Tuple

from tools.comparar_com_patch import APOIO, IMAGEM, docker

RAIZ_DO_REPOSITORIO = Path(__file__).resolve().parent.parent
SAIDA = RAIZ_DO_REPOSITORIO / "docs" / "mutacoes-do-verificador.md"
PASTAS = ("verifier", "tools", "ref", "vectors")
COMANDO = "make -s -C /repo/verifier BUILD_DIR=/tmp/b test"


class Mutacao(NamedTuple):
    regras: Tuple[str, ...]
    violacao: str
    descricao: str
    trocas: Tuple[Tuple[str, str, str], ...]  # (arquivo, trecho original, trecho mutado)
    sobrevive_porque: Optional[str] = None  # preenchido quando sobreviver é o esperado


MUTACOES: Sequence[Mutacao] = (
    Mutacao(("R1", "R3"), "V1", "raiz não comparada no fim do caminho", (
        ("verifier/merkle.c",
         "    resultado = memcmp(atual, raiz->hash, HASH_BYTES) == 0 ? MERKLE_OK : MERKLE_ENOKEY;",
         "    resultado = MERKLE_OK;"),
    )),
    Mutacao(("R1", "R7"), "V1", "tamanho da prova não conferido com a profundidade", (
        ("verifier/merkle.c",
         "    if (tamanho_irmaos % HASH_BYTES != 0 || tamanho_irmaos / HASH_BYTES != raiz->niveis)",
         "    if (tamanho_irmaos % HASH_BYTES != 0)"),
    )),
    Mutacao(("R2",), "V1", "assinatura do manifesto não conferida", (
        ("verifier/mrauth.c",
         "entrada->manifesto);\n    if (motivo != MERKLE_OK)\n        return motivo;",
         "entrada->manifesto);\n    (void)motivo;"),
    )),
    Mutacao(("R2",), "V1", "autorização da autoridade para a árvore não conferida", (
        ("verifier/mrauth.c",
         "    if (!politica->autoriza_arvore || politica->arvore_ambigua)",
         "    if (politica->arvore_ambigua)"),
    )),
    Mutacao(("R2",), "V1", "árvore com duas autoridades aceita", (
        ("verifier/mrauth.c",
         "    if (!politica->autoriza_arvore || politica->arvore_ambigua)",
         "    if (!politica->autoriza_arvore)"),
    )),
    Mutacao(("R2",), "V1", "manifesto complementar com árvore 0, a da imagem, aceito na leitura", (
        ("verifier/formatos.c",
         "    return saida->arvore != 0 && saida->autoridade != 0 && saida->versao != 0;",
         "    return saida->autoridade != 0 && saida->versao != 0;"),
    )),
    Mutacao(("R2",), "V1", "hash do kernel não conferido", (
        ("verifier/mrauth.c",
         "    if (memcmp(entrada->kernel, manifesto->kernel, HASH_BYTES) != 0)",
         "    if (0)"),
    )),
    Mutacao(("R3",), "V1", "folha sem o número da árvore, no C e no gerador dos testes", (
        ("verifier/merkle.c",
         "        gravar_u32(folha + 1, complementar->arvore);",
         "        gravar_u32(folha + 1, 0);"),
        ("tools/testar_mrauth.py",
         'prefixo = struct.pack(">BIIIQ", 3, arvore, posicao, componente, geracao)',
         'prefixo = struct.pack(">BIIIQ", 3, 0, posicao, componente, geracao)'),
    )),
    Mutacao(("R4",), "V2", "componente da autorização não conferido", (
        ("verifier/formatos.c",
         "                if (atual == componente)\n                    saida->autorizacao = entrada;",
         "                saida->autorizacao = entrada;"),
    )),
    Mutacao(("R4",), "V2", "permissões pedidas não conferidas com a máscara", (
        ("verifier/mrauth.c",
         "    if ((manifesto->permissoes & ~ler_u64(politica->autorizacao + 8)) != 0)",
         "    if (0)"),
    )),
    Mutacao(("R5",), "V3", "versão menor que a aceita passa", (
        ("verifier/mrauth.c",
         "    if (manifesto->versao < versao_anterior)\n        return MERKLE_ROLLBACK;",
         "    if (0)\n        return MERKLE_ROLLBACK;"),
    )),
    Mutacao(("R5",), "V3", "outro manifesto com a versão aceita passa", (
        ("verifier/mrauth.c",
         "    if (aceito && manifesto->versao == versao_anterior &&",
         "    if (0 && aceito && manifesto->versao == versao_anterior &&"),
    )),
    Mutacao(("R5",), "V3", "versão aceita não gravada no estado", (
        ("verifier/mrauth.c",
         "    if (manifesto->versao > versao_anterior &&\n        !montar_estado(",
         "    if (0 && manifesto->versao > versao_anterior &&\n        !montar_estado("),
    )),
    Mutacao(("R6",), "V3", "geração mínima não conferida", (
        ("verifier/mrauth.c",
         "    if (entrada->geracao < valor_registro(&estado->revogacao.geracoes, entrada->componente))",
         "    if (0)"),
    )),
    Mutacao(("R6",), "V3", "assinatura da tabela inicial não conferida", (
        ("verifier/mrauth.c",
         "    if (motivo != MERKLE_OK)\n        return motivo;\n    const struct registros vazio",
         "    (void)motivo;\n    const struct registros vazio"),
    )),
    Mutacao(("R6",), "V3", "assinatura da tabela nova não conferida", (
        ("verifier/mrauth.c",
         "    if (motivo != MERKLE_OK)\n        return motivo;\n\n    const struct tabela_revogacao *anterior",
         "    (void)motivo;\n\n    const struct tabela_revogacao *anterior"),
    )),
    Mutacao(("R6",), "V3", "tabela com versão menor que a aceita passa", (
        ("verifier/mrauth.c",
         "    if (nova.versao < anterior->versao)\n        return MERKLE_ROLLBACK;",
         "    if (0)\n        return MERKLE_ROLLBACK;"),
    )),
    Mutacao(("R6",), "V3", "outra tabela com a versão aceita passa", (
        ("verifier/mrauth.c",
         "            return MERKLE_OK;\n        return MERKLE_ROLLBACK;",
         "            return MERKLE_OK;\n        return MERKLE_OK;"),
    )),
    Mutacao(("R6",), "V3", "geração mínima reduzida numa tabela nova", (
        ("verifier/mrauth.c",
         "        if (valor_registro(&nova.geracoes, ler_u32(registro)) < ler_u64(registro + 4))",
         "        if (0)"),
    )),
    Mutacao(("R7",), "V1", "profundidade do manifesto não conferida", (
        ("verifier/mrauth.c",
         "    if (manifesto->numero_folhas == 0 || manifesto->raiz.niveis != profundidade(manifesto->numero_folhas))",
         "    if (manifesto->numero_folhas == 0)"),
    )),
    Mutacao(("R7",), "V1", "árvore com zero folhas não recusada de cara", (
        ("verifier/mrauth.c",
         "    if (manifesto->numero_folhas == 0 || manifesto->raiz.niveis != profundidade(manifesto->numero_folhas))",
         "    if (manifesto->raiz.niveis != profundidade(manifesto->numero_folhas))"),
    ), sobrevive_porque=(
        "zero folhas pede profundidade 1 e nenhuma posição é menor que zero, "
        "então R7 recusa pela profundidade ou pela posição"
    )),
    Mutacao(("R7",), "V1", "posição não conferida com o número de folhas", (
        ("verifier/merkle.c",
         "    if (complementar && posicao >= complementar->numero_folhas)",
         "    if (0)"),
    )),
)


class Resultado(NamedTuple):
    mutacao: Mutacao
    acusada: bool
    caso: str  # o primeiro caso que mudou de resultado, já resumido

    def problema(self) -> Optional[str]:
        esperado_sobreviver = self.mutacao.sobrevive_porque is not None
        if self.acusada == (not esperado_sobreviver):
            return None
        situacao = "acusada, mas devia sobreviver" if self.acusada else "sobreviveu"
        return f"{self.mutacao.descricao}: {situacao}"


def aplicar(raiz: Path, mutacao: Mutacao) -> None:
    for arquivo, antes, depois in mutacao.trocas:
        caminho = raiz / arquivo
        texto = caminho.read_text(encoding="utf-8")
        if texto.count(antes) != 1:
            raise SystemExit(f"{mutacao.descricao}: o trecho de {arquivo} não aparece uma vez só")
        caminho.write_text(texto.replace(antes, depois), encoding="utf-8")


_ASSERCAO = re.compile(r"^(?P<caso>.*?): esperado \[(?P<esperado>[^\]]*)\], veio (?P<veio>.*?) \(saída (?P<saida>-?\d+)\)")
_VETOR = re.compile(r"^(?P<caso>[^:]+): C=(?P<veio>\S+), Python=\S+, esperado=(?P<esperado>\S+)$")


def primeira_falha(saida: str) -> str:
    """Resume o primeiro caso que mudou de resultado na saída do ``make test``."""
    linhas = saida.splitlines()
    for linha in linhas:
        if "AssertionError: " not in linha:
            continue
        texto = linha.split("AssertionError: ", 1)[1]
        achado = _ASSERCAO.match(texto)
        if not achado:
            return texto[:120]
        esperado = re.findall(r"'(\w+)", achado["esperado"])
        veio = achado["veio"].split(" ")[0] or "nada"
        if achado["saida"].startswith("-"):
            veio += f" (saída {achado['saida']})"
        return f"`{achado['caso']}`: esperado {' ou '.join(esperado)}, veio {veio}"
    for linha in linhas:
        achado = _VETOR.match(linha.strip())
        if achado:
            return f"vetor `{achado['caso']}`: esperado {achado['esperado']}, veio {achado['veio']}"
    for linha in linhas:
        if "error:" in linha:
            return "não compilou"
    resto = [l for l in linhas if l.strip() and not l.startswith("make")]
    return resto[-1][:120] if resto else "falhou sem mensagem"


def rodar(mutacao: Optional[Mutacao]) -> Tuple[bool, str]:
    """(passou, saída) do ``make test`` numa cópia, com a mutação aplicada."""
    with tempfile.TemporaryDirectory() as pasta:
        raiz = Path(pasta)
        for nome in PASTAS:
            shutil.copytree(RAIZ_DO_REPOSITORIO / nome, raiz / nome,
                            ignore=shutil.ignore_patterns("build", "__pycache__"))
        if mutacao is not None:
            aplicar(raiz, mutacao)
        execucao = docker("run", "--rm", "-v", f"{raiz}:/repo:ro", IMAGEM, "sh", "-c", COMANDO)
        return execucao.returncode == 0, execucao.stdout + execucao.stderr


def medir() -> List[Resultado]:
    if docker("info").returncode != 0:
        raise SystemExit("Precisa do Docker rodando.")
    construcao = docker("build", "-q", "-t", IMAGEM, str(APOIO))
    if construcao.returncode != 0:
        raise SystemExit(f"não consegui montar a imagem:\n{construcao.stderr}")
    passou, saida = rodar(None)
    if not passou:
        raise SystemExit(f"os testes já falham sem mutação nenhuma:\n{saida}")

    def uma(mutacao: Mutacao) -> Resultado:
        passou, saida = rodar(mutacao)
        return Resultado(mutacao, not passou, "" if passou else primeira_falha(saida))

    with ThreadPoolExecutor(max_workers=4) as execucoes:
        return list(execucoes.map(uma, MUTACOES))


def relatorio(resultados: Sequence[Resultado]) -> str:
    acusadas = sum(r.acusada for r in resultados)
    linhas = [
        f"{acusadas} de {len(resultados)} mutações acusadas.",
        "",
        "| Regra | Violação | Checagem retirada | Resultado | Primeiro caso que mudou |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in resultados:
        m = r.mutacao
        if r.acusada:
            situacao = "acusada"
        elif m.sobrevive_porque:
            situacao = "sobrevive, como esperado"
        else:
            situacao = "**sobreviveu**"
        linhas.append(f"| {', '.join(m.regras)} | {m.violacao} | {m.descricao} | {situacao} | {r.caso or '–'} |")

    esperadas = [r for r in resultados if not r.acusada and r.mutacao.sobrevive_porque]
    if esperadas:
        linhas += ["", "## Por que sobrevive", ""]
        linhas += [f"- **{r.mutacao.descricao}:** {r.mutacao.sobrevive_porque}." for r in esperadas]

    problemas = [p for p in (r.problema() for r in resultados) if p]
    if problemas:
        linhas += ["", "## Problemas", ""]
        linhas += [f"- {p}" for p in problemas]
    return "\n".join(linhas)


def main() -> int:
    resultados = medir()
    texto = relatorio(resultados)
    print(texto)
    if "--gravar" in sys.argv[1:]:
        cabecalho = (
            "# Mutações do verificador em C: resultado bruto\n\n"
            "Gerado por `python3 -m tools.mutar_verificador --gravar` (precisa de Docker). "
            "Cada linha tira uma checagem do verificador numa cópia do repositório e roda "
            "`make -C verifier test` no Debian 13. A leitura está em `docs/argumento-de-seguranca.md`.\n\n"
            "Acusada quer dizer que algum teste percebeu a falta da checagem. Não quer dizer que o "
            "ataque passaria: às vezes outra checagem recusa com outro motivo, e a coluna da direita "
            "mostra qual.\n\n"
        )
        SAIDA.write_text(cabecalho + texto + "\n", encoding="utf-8")
        print(f"\ngravado em {SAIDA.relative_to(RAIZ_DO_REPOSITORIO)}")
    problemas = [p for p in (r.problema() for r in resultados) if p]
    print("\ntudo certo" if not problemas else "\nHÁ PROBLEMAS")
    return 0 if not problemas else 1


if __name__ == "__main__":
    sys.exit(main())
