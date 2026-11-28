"""Conjuntos de teste do benchmark (``tools/conjuntos.py``).

Confere as árvores complementares contra o modelo e contra as provas que os
testes do verificador em C usam, os formatos contra ``spec/README.md`` e que a
tabela gravada está em dia. A geração dos arquivos assinados só roda se houver
OpenSSL 3.5 ou mais novo.
"""

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from ref.merkle import MerkleTree, hash_entry
from tools import conjuntos
from tools.conjuntos import (
    KERNEL,
    ArvoreComEnderecos,
    SoTamanho,
    arvore_complementar,
    corpo_manifesto,
    documento,
    folha_complementar,
    medir,
    montar_arvores,
    montar_metadados,
    no_com_endereco,
    texto_csv,
)
from tools.tamanhos_de_prova import medir as medir_tamanhos
from tools.testar_mrauth import montar_prova

from .modulos import modulos

RAIZ = Path(__file__).resolve().parent.parent


def subir(prova, folha, arvore=None):
    """Sobe uma prova como o verificador em C: nó do patch, ou com endereço se ``arvore`` vier."""
    (pos,) = struct.unpack(">I", prova[:4])
    atual = folha
    irmaos = [prova[4 + 32 * i : 36 + 32 * i] for i in range((len(prova) - 4) // 32)]
    for nivel, irmao in enumerate(irmaos):
        esquerdo, direito = (atual, irmao) if pos & 1 == 0 else (irmao, atual)
        atual = hash_entry(esquerdo, direito) if arvore is None else no_com_endereco(arvore, nivel, pos >> 1, esquerdo, direito)
        pos >>= 1
    return atual


class FolhaComplementar(unittest.TestCase):
    def test_conferida_na_mao(self):
        esperado = hashlib.sha256(struct.pack(">BIIIQ", 3, 7, 5, 42, 2) + b"modulo").digest()
        self.assertEqual(folha_complementar(7, 42, 2)(5, b"modulo"), esperado)


class ArvoresComplementares(unittest.TestCase):
    def test_padrao_igual_ao_modelo_com_a_folha_complementar(self):
        for n in (1, 2, 3, 8, 13):
            with self.subTest(n=n):
                mods = modulos(n)
                gerada = arvore_complementar("padrao", 7, 42, 2, mods)
                modelo = MerkleTree(mods, leaf_hash=folha_complementar(7, 42, 2))
                self.assertEqual(gerada.root, modelo.root)
                self.assertEqual([gerada.proof(i) for i in range(n)], [modelo.proof(i) for i in range(n)])

    def test_igual_as_provas_dos_testes_do_c(self):
        # tools/testar_mrauth.py monta raiz, profundidade e prova do último módulo.
        for variante, formato in conjuntos.VARIANTES.items():
            for n in range(1, 10):
                with self.subTest(variante=variante, n=n):
                    mods = modulos(n)
                    gerada = arvore_complementar(variante, 7, 42, 2, mods)
                    self.assertEqual((gerada.root.hash, gerada.root.levels, gerada.proof(n - 1)),
                                     montar_prova(7, 42, 2, formato, mods))

    def test_toda_prova_com_enderecos_sobe_ate_a_raiz(self):
        for n in (1, 2, 3, 5, 8, 17):
            arvore = ArvoreComEnderecos(9, [folha_complementar(9, 1, 1)(i, m) for i, m in enumerate(modulos(n))])
            for i, mod in enumerate(modulos(n)):
                with self.subTest(n=n, posicao=i):
                    folha = folha_complementar(9, 1, 1)(i, mod)
                    self.assertEqual(subir(arvore.proof(i), folha, arvore=9), arvore.root.hash)

    def test_endereco_muda_a_raiz(self):
        mods = modulos(8)
        self.assertNotEqual(arvore_complementar("padrao", 7, 1, 1, mods).root, arvore_complementar("enderecos", 7, 1, 1, mods).root)
        self.assertNotEqual(arvore_complementar("enderecos", 7, 1, 1, mods).root, arvore_complementar("enderecos", 8, 1, 1, mods).root)

    def test_arvore_sem_folhas(self):
        with self.assertRaises(ValueError):
            ArvoreComEnderecos(1, [])


class DivisaoEmRaizes(unittest.TestCase):
    def test_principal_no_formato_do_patch_e_complementares_numeradas(self):
        arvores = montar_arvores("padrao", 128, 4)
        self.assertEqual([a.id for a in arvores], [0, 1, 2, 3])
        self.assertEqual(arvores[0].raiz, MerkleTree(modulos(32)).root)
        self.assertEqual(arvores[2].modulos, modulos(32, inicio=64))
        self.assertEqual((arvores[2].componente, arvores[2].geracao), (2, 1))

    def test_mesmas_provas_da_tabela_de_tamanhos(self):
        tamanhos = {(l["modulos"], l["raizes"]): (l["niveis"], l["prova_bytes"]) for l in medir_tamanhos()}
        for linha in medir(ml_dsa=[44]):
            with self.subTest(variante=linha["variante"], modulos=linha["modulos"], raizes=linha["raizes"]):
                self.assertEqual((linha["niveis"], linha["prova_bytes"]), tamanhos[(linha["modulos"], linha["raizes"])])

    def test_divisao_sem_sobra(self):
        with self.assertRaises(ValueError):
            montar_arvores("padrao", 100, 16)


class Formatos(unittest.TestCase):
    """Posições e tamanhos de ``spec/README.md`` e de ``verifier/formatos.c``."""

    def setUp(self):
        self.arvores = montar_arvores("padrao", 128, 4)

    def test_manifesto_tem_98_bytes_nos_lugares_do_verificador(self):
        arvore = self.arvores[2]
        corpo = corpo_manifesto(1, arvore)
        self.assertEqual(len(corpo), 98)
        self.assertEqual(corpo[:5], b"AMMF\x01")
        self.assertEqual(struct.unpack(">II", corpo[5:13]), (2, 2))  # árvore e autoridade
        self.assertEqual(struct.unpack(">Q", corpo[13:21])[0], 1)  # versão
        self.assertEqual(corpo[21:53], KERNEL)
        self.assertEqual(struct.unpack(">I", corpo[53:57])[0], 32)  # folhas
        self.assertEqual(corpo[57], arvore.raiz.levels)
        self.assertEqual(corpo[58:90], arvore.raiz.hash)
        self.assertEqual(struct.unpack(">Q", corpo[90:98])[0], 1)  # permissões

    def test_tamanhos_por_conjunto(self):
        for conjunto, (chave, assinatura) in {44: (1312, 2420), 65: (1952, 3309), 87: (2592, 4627)}.items():
            with self.subTest(conjunto=conjunto):
                meta = montar_metadados("padrao", self.arvores, conjunto, SoTamanho(conjunto))
                self.assertEqual(sorted(meta.manifestos), [1, 2, 3])
                self.assertTrue(all(len(m) == 98 + assinatura for m in meta.manifestos.values()))
                # AMPO, versão, conjunto, chave de revogação, quantidade; por autoridade: id, chave, quantidade, uma autorização
                self.assertEqual(len(meta.politica), 4 + 1 + 1 + chave + 4 + 3 * (4 + chave + 4 + 16))
                # AMRV, versão, versão da tabela, quantidade, 3 entradas de 12 bytes, assinatura
                self.assertEqual(len(meta.revogacao), 17 + 3 * 12 + assinatura)
                # AMES, versão, tamanho da tabela, tabela, quantidade, 3 registros de 44 bytes
                self.assertEqual(len(meta.estado), 9 + len(meta.revogacao) + 4 + 3 * 44)

    def test_politica_ordenada_com_uma_autorizacao_por_autoridade(self):
        meta = montar_metadados("padrao", self.arvores, 44, SoTamanho(44))
        self.assertEqual(meta.politica[:6], b"AMPO\x01" + bytes([44]))
        resto = meta.politica[6 + 1312 :]
        self.assertEqual(struct.unpack(">I", resto[:4])[0], 3)
        resto = resto[4:]
        for autoridade in (1, 2, 3):
            self.assertEqual(struct.unpack(">I", resto[:4])[0], autoridade)
            resto = resto[4 + 1312 :]
            self.assertEqual(struct.unpack(">IIIQ", resto[:20]), (1, autoridade, autoridade, 1))
            resto = resto[20:]
        self.assertEqual(resto, b"")

    def test_estado_guarda_o_resumo_do_manifesto(self):
        meta = montar_metadados("padrao", self.arvores, 44, SoTamanho(44))
        registros = meta.estado[9 + len(meta.revogacao) + 4 :]
        self.assertEqual(registros[:12], struct.pack(">IQ", 1, 1))
        self.assertEqual(registros[12:44], hashlib.sha256(corpo_manifesto(1, self.arvores[1])).digest())

    def test_uma_raiz_nao_tem_metadados(self):
        meta = montar_metadados("padrao", montar_arvores("padrao", 128, 1), 44, SoTamanho(44))
        self.assertEqual((meta.manifestos, meta.politica, meta.revogacao, meta.estado), ({}, b"", b"", b""))

    def test_variante_com_enderecos_usa_o_formato_2(self):
        meta = montar_metadados("enderecos", self.arvores, 44, SoTamanho(44))
        self.assertTrue(all(m[:5] == b"AMMF\x02" for m in meta.manifestos.values()))


class TabelaGravada(unittest.TestCase):
    def test_arquivos_em_dia_com_o_gerador(self):
        linhas = medir()
        aviso = "rode: python3 -m tools.conjuntos --gravar"
        self.assertEqual((RAIZ / "bench" / "conjuntos.csv").read_text(encoding="utf-8"), texto_csv(linhas), aviso)
        self.assertEqual((RAIZ / "docs" / "conjuntos.md").read_text(encoding="utf-8"), documento(linhas), aviso)


OPENSSL = conjuntos.achar_openssl()


@unittest.skipUnless(OPENSSL, "precisa de OpenSSL 3.5 ou mais novo")
class ArquivosAssinados(unittest.TestCase):
    def gerar(self, pasta):
        conjuntos.gravar_arquivos(pasta, OPENSSL, ["padrao", "enderecos"], [128], [4], [44])
        return {p.relative_to(pasta): p.read_bytes() for p in sorted(pasta.rglob("*.bin"))}

    def test_reproduziveis_e_do_tamanho_da_tabela(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            primeira, segunda = self.gerar(Path(a)), self.gerar(Path(b))
        self.assertEqual(primeira, segunda)

        linha = next(l for l in medir(["padrao"], [128], [4], [44]))
        pasta = Path("padrao/128x4/ml-dsa-44")
        self.assertEqual(len(primeira[pasta / "politica.bin"]), linha["politica_bytes"])
        self.assertEqual(len(primeira[pasta / "revogacao.bin"]), linha["revogacao_bytes"])
        self.assertEqual(len(primeira[pasta / "manifesto-1.bin"]), linha["manifesto_bytes"])
        raiz = montar_arvores("padrao", 128, 4)[0].raiz
        self.assertEqual(primeira[Path("padrao/128x4/raiz.bin")], struct.pack(">I", raiz.levels) + raiz.hash)


if __name__ == "__main__":
    unittest.main()
