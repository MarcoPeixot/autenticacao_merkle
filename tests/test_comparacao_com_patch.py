"""Partes da comparação com o patch que não precisam de Docker.

A comparação em si (``python3 -m tools.comparar_com_patch``) roda num
container. Aqui ficam a conferência dos arquivos de ``patch-v5/`` e os
formatos que o script lê e escreve.
"""

import unittest

from ref.merkle import EMPTY_ROOT, MerkleTree
from tools.comparar_com_patch import (
    MARCADOR,
    TIPO_MERKLE,
    arquivo_de_prova,
    conferir_origem,
    ler_raiz_em_c,
    prova_do_arquivo,
    raiz_em_c,
)

from .modulos import modulos


class ArquivosDoPatch(unittest.TestCase):
    def test_patch_v5_tem_os_arquivos_do_patch_sem_alteracao(self):
        for nome, calculado, origem, ok in conferir_origem():
            with self.subTest(arquivo=nome):
                self.assertTrue(ok, f"{nome}: blob {calculado}, esperado o de {origem}")


class ArquivoDaRaiz(unittest.TestCase):
    def test_raiz_vazia_no_formato_da_ferramenta(self):
        zeros = "\n".join(["\t\t" + " ".join(["0x00,"] * 8)] * 4)
        esperado = (
            "#include <linux/module_hashes.h>\n\n"
            "const struct\n"
            "module_hashes_root module_hashes_root __module_hashes_section = {\n"
            "\t.levels = 0,\n"
            "\t.hash = {{\n" + zeros + "\n\t}},\n};\n"
        )
        self.assertEqual(raiz_em_c(EMPTY_ROOT), esperado)

    def test_ida_e_volta(self):
        for n in (1, 2, 13, 100):
            with self.subTest(n=n):
                raiz = MerkleTree(modulos(n)).root
                self.assertEqual(ler_raiz_em_c(raiz_em_c(raiz)), raiz)


class ArquivoDeProva(unittest.TestCase):
    def test_rodape(self):
        prova = MerkleTree(modulos(13)).proof(5)
        dados = arquivo_de_prova(prova)
        self.assertEqual(len(dados), len(prova) + 12 + len(MARCADOR))
        self.assertTrue(dados.startswith(prova))
        self.assertTrue(dados.endswith(MARCADOR))
        self.assertEqual(dados[len(prova) + 2], TIPO_MERKLE)
        self.assertEqual(int.from_bytes(dados[len(prova) + 8 : len(prova) + 12], "big"), len(prova))

    def test_separa_a_prova_do_rodape(self):
        arvore = MerkleTree(modulos(13))
        for i in range(13):
            with self.subTest(modulo=i):
                self.assertEqual(prova_do_arquivo(arquivo_de_prova(arvore.proof(i))), arvore.proof(i))

    def test_recusa_arquivo_sem_marcador(self):
        with self.assertRaises(ValueError):
            prova_do_arquivo(MerkleTree(modulos(3)).proof(0))


if __name__ == "__main__":
    unittest.main()
