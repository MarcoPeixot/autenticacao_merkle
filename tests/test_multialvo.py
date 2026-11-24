"""Hipótese multi-alvo.

O nó interno não leva nível, índice nem árvore, então um hash calculado pelo
atacante pode coincidir com qualquer nó. Estes testes rodam a busca do
experimento com poucos bits e conferem onde uma coincidência vira prova aceita.
"""

import hashlib
import unittest

from ref.merkle import ENOKEY, HASH_SIZE, OK, MerkleTree, hash_data, hash_entry, module_hash_check
from ref.variantes import hash_data_com_arvore, truncado, truncar
from tools.experimento_multialvo import ESQUEMAS, MALICIOSO, atacar

from .modulos import modulos

BITS = 8
POR_ARVORE = 8
ARVORES = (1, 4)
TENTATIVAS = 2 ** 12


def buscar(esquema, altura=1):
    return atacar(ESQUEMAS[esquema], BITS, ARVORES, POR_ARVORE, TENTATIVAS, altura)


class Truncamento(unittest.TestCase):
    def test_mantem_o_tamanho_e_zera_o_resto(self):
        cheio = hashlib.sha256(b"abc").digest()
        curto = truncar(cheio, 16)
        self.assertEqual(len(curto), HASH_SIZE)
        self.assertEqual(curto[:2], cheio[:2])
        self.assertEqual(curto[2:], bytes(HASH_SIZE - 2))

    def test_quantidade_de_bits_que_nao_fecha_um_byte(self):
        cheio = bytes([0xFF]) * HASH_SIZE
        self.assertEqual(truncar(cheio, 14), bytes([0xFF, 0xFC]) + bytes(HASH_SIZE - 2))
        self.assertEqual(truncar(cheio, 1), bytes([0x80]) + bytes(HASH_SIZE - 1))

    def test_com_256_bits_nada_muda(self):
        self.assertEqual(truncado(hash_entry, 256)(b"a" * 32, b"b" * 32), hash_entry(b"a" * 32, b"b" * 32))
        self.assertEqual(truncado(hash_data, 256)(7, b"modulo"), hash_data(7, b"modulo"))


class ModeloComOutroHashDeNo(unittest.TestCase):
    def test_o_padrao_e_o_hash_do_patch(self):
        m = modulos(13)
        self.assertEqual(MerkleTree(m).root, MerkleTree(m, node_hash=hash_entry).root)

    def test_prova_legitima_passa_com_hash_truncado(self):
        folha, no = truncado(hash_data, 12), truncado(hash_entry, 12)
        m = modulos(13)
        arvore = MerkleTree(m, folha, no)
        for i in range(len(m)):
            with self.subTest(modulo=i):
                self.assertEqual(module_hash_check(arvore.root, m[i], arvore.proof(i), folha, no), OK)

    def test_o_verificador_usa_o_hash_de_no_que_recebe(self):
        folha, no = truncado(hash_data, 12), truncado(hash_entry, 12)
        m = modulos(13)
        arvore = MerkleTree(m, folha, no)
        self.assertEqual(module_hash_check(arvore.root, m[0], arvore.proof(0), folha), ENOKEY)


class FolhaComArvore(unittest.TestCase):
    def test_formula(self):
        esperado = hashlib.sha256(b"\x01" + bytes([0, 0, 0, 3]) + bytes([0, 0, 0, 5]) + b"modulo").digest()
        self.assertEqual(hash_data_com_arvore(3)(5, b"modulo"), esperado)

    def test_a_mesma_folha_muda_de_uma_arvore_para_outra(self):
        self.assertNotEqual(hash_data_com_arvore(0)(5, b"modulo"), hash_data_com_arvore(1)(5, b"modulo"))


class Busca(unittest.TestCase):
    def test_o_modulo_do_atacante_nao_esta_em_arvore_nenhuma(self):
        self.assertNotIn(MALICIOSO, modulos(POR_ARVORE * max(ARVORES)))

    def test_as_contagens_fecham(self):
        for esquema in ESQUEMAS:
            for c in buscar(esquema):
                with self.subTest(esquema=esquema, arvores=c.arvores):
                    self.assertGreater(c.coincidencias, 0)
                    self.assertEqual(
                        c.coincidencias,
                        c.recusadas_tamanho + c.recusadas_caminho + c.aceitas + c.aceitas_por_acaso,
                    )

    def test_no_patch_a_prova_so_fecha_no_indice_zero(self):
        uma, quatro = buscar("patch")
        for c in (uma, quatro):
            with self.subTest(arvores=c.arvores):
                self.assertGreater(c.aceitas, 0)
                self.assertTrue(all(nivel == 1 and indice == 0 for _, nivel, indice in c.onde), c.onde)
                # A maior parte das coincidências é com outro índice ou outro nível.
                self.assertGreater(c.recusadas_caminho, 0)
                self.assertGreater(c.recusadas_tamanho, 0)

    def test_no_patch_cada_arvore_a_mais_e_um_alvo_a_mais(self):
        uma, quatro = buscar("patch")
        self.assertEqual({a for a, _, _ in uma.onde}, {0})
        self.assertGreater(len({a for a, _, _ in quatro.onde}), 1)
        self.assertGreater(quatro.aceitas, uma.aceitas)

    def test_sem_posicao_fecha_em_qualquer_no_do_nivel(self):
        uma, _ = buscar("folha sem posição")
        self.assertTrue(all(nivel == 1 for _, nivel, _ in uma.onde), uma.onde)
        self.assertGreater(len({indice for _, _, indice in uma.onde}), 1)
        self.assertEqual(uma.recusadas_caminho, 0)
        self.assertGreater(uma.aceitas, buscar("patch")[0].aceitas)

    def test_com_a_arvore_na_folha_so_fecha_na_arvore_declarada(self):
        uma, quatro = buscar("folha com árvore")
        self.assertEqual(quatro.onde, {(0, 1, 0)})
        self.assertEqual(quatro.aceitas, uma.aceitas)

    def test_subarvore_falsa_mais_alta_segue_a_mesma_regra(self):
        for altura in (2, 3):
            with self.subTest(altura=altura):
                _, quatro = buscar("patch", altura)
                self.assertGreater(quatro.aceitas, 0)
                self.assertTrue(all(nivel == altura and indice == 0 for _, nivel, indice in quatro.onde), quatro.onde)


if __name__ == "__main__":
    unittest.main()
