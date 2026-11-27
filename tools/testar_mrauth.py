import hashlib
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ref.merkle import MerkleTree

CHAVE_BYTES = {44: 1312, 65: 1952, 87: 2592}
KERNEL = hashlib.sha256(b"kernel do teste").digest()
MODULOS = (b"primeiro", b"segundo", b"terceiro", b"quarto", b"modulo complementar")
COMPONENTE = 42


def executar(*args):
    return subprocess.check_output(args)


def montar_prova(arvore, componente, geracao, formato):
    def folha(posicao, modulo):
        prefixo = struct.pack(">BIIIQ", 3, arvore, posicao, componente, geracao)
        return hashlib.sha256(prefixo + modulo).digest()

    posicao = len(MODULOS) - 1
    if formato == 1:
        referencia = MerkleTree(MODULOS, leaf_hash=folha)
        return referencia.root.hash, referencia.root.levels, referencia.proof(posicao)

    irmaos = [struct.pack(">I", posicao)]
    nos = [folha(i, modulo) for i, modulo in enumerate(MODULOS)]
    nivel = 0
    while len(nos) > 1:
        if len(nos) % 2:
            nos.append(nos[-1])
        irmaos.append(nos[posicao ^ 1])
        nos = [
            hashlib.sha256(struct.pack(">BIBI", 4, arvore, nivel, i // 2) + nos[i] + nos[i + 1]).digest()
            for i in range(0, len(nos), 2)
        ]
        nivel += 1
        posicao >>= 1
    return nos[0], nivel, b"".join(irmaos)


class Cenario:
    def __init__(self, pasta, verificador, formato, conjunto):
        self.pasta = pasta
        self.verificador = verificador
        self.formato = formato
        self.estado = pasta / "estado"
        self.casos = 0
        self.chaves = {}
        publicas = {}
        for autoridade in (0, 1, 2):
            chave = pasta / f"chave{autoridade}.pem"
            executar("openssl", "genpkey", "-algorithm", f"ML-DSA-{conjunto}", "-out", chave)
            der = executar("openssl", "pkey", "-in", chave, "-pubout", "-outform", "DER")
            publicas[autoridade] = der[-CHAVE_BYTES[conjunto]:]
            self.chaves[autoridade] = chave

        politica = b"AMPO\x01" + bytes([conjunto]) + publicas[0] + struct.pack(">I", 2)
        for autoridade, arvore in ((1, 7), (2, 3)):
            politica += (
                struct.pack(">I", autoridade) + publicas[autoridade] +
                struct.pack(">IIIQ", 1, arvore, COMPONENTE, 3)
            )
        self.politica = self.arquivo("politica", politica)

    def arquivo(self, nome, dados):
        caminho = self.pasta / nome
        caminho.write_bytes(dados)
        return caminho

    def assinar(self, corpo, autoridade):
        entrada = self.arquivo("corpo", corpo)
        return corpo + executar(
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.chaves[autoridade], "-in", entrada
        )

    def tabela(self, versao, geracoes=(), autoridade=0):
        corpo = struct.pack(">4sBQI", b"AMRV", 1, versao, len(geracoes))
        corpo += b"".join(struct.pack(">IQ", componente, minimo) for componente, minimo in geracoes)
        return self.assinar(corpo, autoridade)

    def manifesto(self, *, arvore=7, autoridade=1, versao=1, componente=COMPONENTE, geracao=2,
                  permissoes=1, folhas=len(MODULOS), ajustar_niveis=0, formato=None):
        raiz, niveis, prova = montar_prova(arvore, componente, geracao, self.formato)
        corpo = struct.pack(
            ">4sBIIQ32sIB32sQ", b"AMMF", formato or self.formato, arvore, autoridade, versao, KERNEL,
            folhas, niveis + ajustar_niveis, raiz, permissoes,
        )
        manifesto = self.assinar(corpo, autoridade if autoridade in self.chaves else 1)
        return manifesto, prova, raiz

    def argumentos(self, nome, manifesto, prova, *, modulo=MODULOS[-1], componente=COMPONENTE,
                   geracao=2, kernel=KERNEL, politica=None):
        return (
            "complementar", politica or self.politica, self.estado, kernel.hex(),
            self.arquivo(nome + ".manifesto", manifesto), str(componente), str(geracao),
            self.arquivo(nome + ".modulo", modulo), self.arquivo(nome + ".prova", prova),
        )

    def conferir(self, nome, motivos, args, raiz=None, autoridade=1):
        if isinstance(motivos, str):
            motivos = (motivos,)
        identificacao = f"{raiz.hex()} {autoridade}" if raiz is not None else "- -"
        esperado = [f"{motivo} {identificacao}" for motivo in motivos]
        resultado = subprocess.run((self.verificador, *args), stdout=subprocess.PIPE, text=True)
        linha = resultado.stdout.strip()
        status = 0 if linha.startswith("OK ") else 1
        if linha not in esperado or resultado.returncode != status:
            raise AssertionError(f"{nome}: esperado {esperado}, veio {linha} (saída {resultado.returncode})")
        self.casos += 1

    def verificar(self, nome, motivo, manifesto, prova, raiz=None, autoridade=1, **campos):
        argumentos = self.argumentos(nome, manifesto, prova, **campos)
        self.conferir(nome, motivo, argumentos, raiz, autoridade)

    def gerir(self, comando, nome, motivo, tabela):
        argumentos = comando, self.politica, self.estado, self.arquivo(nome, tabela)
        self.conferir(nome, motivo, argumentos)


def testar(executavel, formato, conjunto, pasta, completo):
    caso = Cenario(pasta, executavel, formato, conjunto)
    inicial = caso.tabela(1)
    caso.gerir("iniciar", "assinante errado", "ASSINATURA_INVALIDA", caso.tabela(1, autoridade=1))
    caso.gerir("iniciar", "provisionar", "OK", inicial)
    caso.gerir("iniciar", "preservar estado", "ESTADO_EXISTENTE", inicial)

    manifesto, prova, raiz = caso.manifesto()
    caso.verificar("aceite", "OK", manifesto, prova, raiz)
    manifesto_v2, _, _ = caso.manifesto(versao=2)
    caso.verificar("atualizar", "OK", manifesto_v2, prova, raiz)
    caso.verificar("versao antiga", "ROLLBACK", manifesto, prova, raiz)
    if not completo:
        return caso.casos

    caso.verificar("assinatura alterada", "ASSINATURA_INVALIDA",
                   manifesto_v2[:-1] + bytes([manifesto_v2[-1] ^ 1]), prova)
    caso.verificar("assinatura truncada", "FORMATO_INVALIDO", manifesto_v2[:-1], prova)
    caso.verificar("kernel", "KERNEL_INCOMPATIVEL", manifesto_v2, prova, kernel=bytes(32))
    caso.verificar("prova curta", "ENOPKG", manifesto_v2, prova[:-1], raiz)
    caso.verificar("posicao", "POSICAO_INVALIDA", manifesto_v2, struct.pack(">I", len(MODULOS)) + prova[4:], raiz)
    caso.verificar("modulo alterado", "ENOKEY", manifesto_v2, prova, raiz, modulo=b"outro")
    caso.verificar("geracao divergente", "ENOKEY", manifesto_v2, prova, raiz, geracao=3)
    invalido, _, _ = caso.manifesto(versao=3, ajustar_niveis=1)
    caso.verificar("niveis", "FORMATO_INVALIDO", invalido, prova, raiz)
    vazio, _, _ = caso.manifesto(versao=3, folhas=0)
    caso.verificar("arvore complementar vazia", "FORMATO_INVALIDO", vazio, prova, raiz)
    outro_formato, _, _ = caso.manifesto(versao=2, formato=3 - formato)
    caso.verificar("formato de manifesto", "FORMATO_INVALIDO", outro_formato, prova)

    desconhecido, _, _ = caso.manifesto(versao=2, autoridade=3)
    caso.verificar("autoridade desconhecida", "AUTORIDADE_NAO_AUTORIZADA", desconhecido, prova)
    fora_da_politica, _, _ = caso.manifesto(versao=2, autoridade=2)
    caso.verificar("autoridade fora da arvore", "AUTORIDADE_NAO_AUTORIZADA", fora_da_politica, prova)
    sem_permissao, _, _ = caso.manifesto(versao=3, permissoes=9)
    caso.verificar("permissao", "PERMISSAO_NEGADA", sem_permissao, prova, raiz)
    outro_componente, prova_componente, raiz_componente = caso.manifesto(versao=3, componente=0)
    caso.verificar("componente", "COMPONENTE_NAO_AUTORIZADO", outro_componente, prova_componente,
                   raiz_componente, componente=0)
    politica_incompleta = caso.arquivo("politica incompleta", b"AMPO\x01" + bytes([conjunto]) + bytes(4))
    caso.verificar("politica incompleta", "FORMATO_INVALIDO", manifesto_v2, prova, politica=politica_incompleta)

    outro, prova_outra, raiz_outra = caso.manifesto(arvore=3, autoridade=2)
    caso.verificar("prova de outra arvore", "ENOKEY", outro, prova, raiz_outra, 2)
    caso.verificar("versao por arvore", "OK", outro, prova_outra, raiz_outra, 2)
    manifesto_v3, _, _ = caso.manifesto(versao=3)
    caso.verificar("recusa preserva versao", "ENOKEY", manifesto_v3, prova, raiz, modulo=b"outro")
    caso.verificar("versao anterior preservada", "OK", manifesto_v2, prova, raiz)
    mesma_versao, _, _ = caso.manifesto(versao=2, permissoes=3)
    caso.verificar("mesma versao com outro manifesto", "ROLLBACK", mesma_versao, prova, raiz)
    reassinado, _, _ = caso.manifesto(versao=2)
    caso.verificar("mesma versao reassinada", "OK", reassinado, prova, raiz)

    revogacao = caso.tabela(2, ((COMPONENTE, 3),))
    caso.gerir("revogar", "revogar", "OK", revogacao)
    caso.gerir("revogar", "repetir revogacao", "OK", caso.tabela(2, ((COMPONENTE, 3),)))
    caso.gerir("revogar", "tabela antiga", "ROLLBACK", inicial)
    caso.gerir("revogar", "mesma versao de tabela", "ROLLBACK", caso.tabela(2, ((COMPONENTE, 4),)))
    caso.gerir("revogar", "diminuir minimo", "REVOGACAO_REGRESSIVA", caso.tabela(3))
    caso.verificar("geracao revogada", "REVOGADO", manifesto_v3, prova, raiz)
    recente, prova_recente, raiz_recente = caso.manifesto(versao=3, geracao=3)
    caso.verificar("geracao permitida", "OK", recente, prova_recente, raiz_recente, geracao=3)

    versao4, _, _ = caso.manifesto(versao=4, geracao=3)
    versao5, _, _ = caso.manifesto(versao=5, geracao=3)
    args4 = caso.argumentos("simultaneo4", versao4, prova_recente, geracao=3)
    args5 = caso.argumentos("simultaneo5", versao5, prova_recente, geracao=3)
    with ThreadPoolExecutor(max_workers=2) as processos:
        baixa = processos.submit(caso.conferir, "versao 4 concorrente", ("OK", "ROLLBACK"), args4, raiz_recente)
        alta = processos.submit(caso.conferir, "versao 5 concorrente", "OK", args5, raiz_recente)
        baixa.result()
        alta.result()
    caso.conferir("estado depois de concorrencia", "ROLLBACK", args4, raiz_recente)
    return caso.casos


def main(padrao, enderecos):
    total = 0
    for verificador, formato, conjunto in ((padrao, 1, 44), (enderecos, 2, 44), (padrao, 1, 65), (padrao, 1, 87)):
        with tempfile.TemporaryDirectory() as pasta:
            total += testar(verificador, formato, conjunto, Path(pasta), conjunto == 44)
    print(f"{total} checagens de múltiplas raízes nas duas compilações e nos três conjuntos ML-DSA.")


if __name__ == "__main__":
    main(*sys.argv[1:])
