"""O que o verificador de raiz única tem de recusar.

Cada teste mira uma checagem de ``module_hash_check()``: o tamanho da prova
(ENOPKG) ou a comparação do caminho recalculado com a raiz (ENOKEY).
"""

import unittest

from ref.merkle import ENOKEY, ENOPKG, HASH_SIZE, OK, MerkleTree, Root, make_proof, module_hash_check

from .modulos import modulos

N = 13  # ímpar, 4 níveis: há nós pareados consigo mesmos em mais de um nível


def inverte_bit(dados: bytes, indice: int = 0) -> bytes:
    return dados[:indice] + bytes([dados[indice] ^ 0x01]) + dados[indice + 1 :]


class Rejeicoes(unittest.TestCase):
    def setUp(self):
        self.m = modulos(N)
        self.arvore = MerkleTree(self.m)
        self.raiz = self.arvore.root

    def test_controle_as_provas_legitimas_passam(self):
        for i in range(N):
            self.assertEqual(module_hash_check(self.raiz, self.m[i], self.arvore.proof(i)), OK)

    # --- ligação entre o módulo e a folha -------------------------------

    def test_modulo_com_um_bit_alterado(self):
        for i in range(N):
            with self.subTest(i=i):
                alterado = inverte_bit(self.m[i], len(self.m[i]) // 2)
                self.assertEqual(module_hash_check(self.raiz, alterado, self.arvore.proof(i)), ENOKEY)

    def test_modulo_com_byte_a_mais_ou_a_menos(self):
        for i in range(N):
            prova = self.arvore.proof(i)
            with self.subTest(i=i):
                self.assertEqual(module_hash_check(self.raiz, self.m[i] + b"\x00", prova), ENOKEY)
                self.assertEqual(module_hash_check(self.raiz, self.m[i][:-1], prova), ENOKEY)

    def test_prova_de_outro_modulo(self):
        for i in range(N):
            for j in range(N):
                if i == j:
                    continue
                with self.subTest(modulo=i, prova=j):
                    self.assertEqual(module_hash_check(self.raiz, self.m[i], self.arvore.proof(j)), ENOKEY)

    # --- checagem de tamanho --------------------------------------------

    def test_prova_truncada(self):
        prova = self.arvore.proof(4)
        for corte in (1, HASH_SIZE - 1, HASH_SIZE, HASH_SIZE + 1, len(prova) - 4, len(prova)):
            with self.subTest(corte=corte):
                self.assertEqual(module_hash_check(self.raiz, self.m[4], prova[: len(prova) - corte]), ENOPKG)

    def test_prova_alongada(self):
        prova = self.arvore.proof(4)
        for extra in (b"\x00", bytes(HASH_SIZE), prova[4 : 4 + HASH_SIZE]):
            with self.subTest(extra=len(extra)):
                self.assertEqual(module_hash_check(self.raiz, self.m[4], prova + extra), ENOPKG)

    # --- caminho até a raiz ---------------------------------------------

    def test_qualquer_irmao_alterado(self):
        irmaos = self.arvore.siblings(6)
        for nivel in range(len(irmaos)):
            alterados = list(irmaos)
            alterados[nivel] = inverte_bit(alterados[nivel])
            with self.subTest(nivel=nivel):
                self.assertEqual(module_hash_check(self.raiz, self.m[6], make_proof(6, alterados)), ENOKEY)

    def test_irmaos_fora_de_ordem(self):
        irmaos = self.arvore.siblings(6)
        for a in range(len(irmaos)):
            for b in range(a + 1, len(irmaos)):
                trocados = list(irmaos)
                trocados[a], trocados[b] = trocados[b], trocados[a]
                with self.subTest(a=a, b=b):
                    self.assertEqual(module_hash_check(self.raiz, self.m[6], make_proof(6, trocados)), ENOKEY)

    # --- raiz -----------------------------------------------------------

    def test_prova_contra_a_raiz_de_outra_arvore_de_mesma_altura(self):
        outros = [x + b"-outra" for x in self.m]
        raiz_alheia = MerkleTree(outros).root
        self.assertEqual(raiz_alheia.levels, self.raiz.levels)
        for i in range(N):
            with self.subTest(i=i):
                self.assertEqual(module_hash_check(raiz_alheia, self.m[i], self.arvore.proof(i)), ENOKEY)

    def test_prova_contra_a_raiz_de_arvore_de_outra_altura(self):
        for n in (2, 4, 40):
            raiz_alheia = MerkleTree(modulos(n)).root
            with self.subTest(n=n):
                self.assertNotEqual(raiz_alheia.levels, self.raiz.levels)
                self.assertEqual(module_hash_check(raiz_alheia, self.m[0], self.arvore.proof(0)), ENOPKG)

    def test_numero_de_niveis_da_raiz_adulterado(self):
        for niveis in (self.raiz.levels - 1, self.raiz.levels + 1, 0):
            with self.subTest(niveis=niveis):
                raiz = Root(niveis, self.raiz.hash)
                self.assertEqual(module_hash_check(raiz, self.m[0], self.arvore.proof(0)), ENOPKG)


if __name__ == "__main__":
    unittest.main()
