"""Hipótese do uso indevido da posição.

O campo ``pos`` tem dois usos no patch: os bits baixos guiam o percurso, um
por nível, e os 32 bits entram no hash da folha. Estes testes tentam
aproveitar a diferença entre os dois usos reaproveitando dados legítimos.
A variante sem a posição na folha mostra o que a regra evita.
"""

import unittest

from ref.merkle import ENOKEY, OK, MerkleTree, make_proof, module_hash_check
from ref.variantes import hash_data_sem_posicao
from tools.experimento_posicao import varrer

from .modulos import modulos


class PosicaoNoEsquemaDoPatch(unittest.TestCase):
    def test_posicao_trocada_por_outra_posicao_real(self):
        n = 13
        m = modulos(n)
        arvore = MerkleTree(m)
        for i in range(n):
            for pos in range(n):
                if pos == i:
                    continue
                with self.subTest(modulo=i, pos=pos):
                    prova = make_proof(pos, arvore.siblings(i))
                    self.assertEqual(module_hash_check(arvore.root, m[i], prova), ENOKEY)

    def test_bits_acima_do_percurso(self):
        # pos + k * 2^níveis percorre o mesmo caminho, mas muda o hash da folha.
        n = 13
        m = modulos(n)
        arvore = MerkleTree(m)
        passo = 2 ** arvore.num_levels
        for i in range(n):
            for k in (1, 2, 3, 2 ** (32 - arvore.num_levels) - 1):
                pos = i + k * passo
                self.assertLess(pos, 2 ** 32)
                with self.subTest(modulo=i, pos=pos):
                    prova = make_proof(pos, arvore.siblings(i))
                    self.assertEqual(module_hash_check(arvore.root, m[i], prova), ENOKEY)

    def test_posicoes_que_sobram_em_arvore_incompleta(self):
        # 5 módulos em 3 níveis: as posições 5, 6 e 7 não existem.
        n = 5
        m = modulos(n)
        arvore = MerkleTree(m)
        for i in range(n):
            for pos in range(n, 2 ** arvore.num_levels):
                for j in range(n):
                    with self.subTest(modulo=i, pos=pos, irmaos_de=j):
                        prova = make_proof(pos, arvore.siblings(j))
                        self.assertEqual(module_hash_check(arvore.root, m[i], prova), ENOKEY)

    def test_varredura_completa_de_arvores_pequenas(self):
        for n in range(1, 10):
            with self.subTest(n=n):
                res = varrer(n)
                self.assertEqual(res.legitimas_aceitas, n)
                self.assertEqual(res.legitimas_recusadas, 0)
                self.assertEqual(res.indevidas_aceitas, 0, res.exemplos)


class PosicaoNaVarianteSemPosicaoNaFolha(unittest.TestCase):
    """Sem a posição na folha, as mesmas manipulações passam."""

    def test_no_duplicado_aceita_posicao_que_nao_existe(self):
        # 3 módulos: o módulo 2 é pareado consigo mesmo, e a posição 3 passa a valer.
        m = modulos(3)
        fraca = MerkleTree(m, leaf_hash=hash_data_sem_posicao)
        prova = make_proof(3, fraca.siblings(2))
        self.assertEqual(module_hash_check(fraca.root, m[2], prova, hash_data_sem_posicao), OK)

        patch = MerkleTree(m)
        prova = make_proof(3, patch.siblings(2))
        self.assertEqual(module_hash_check(patch.root, m[2], prova), ENOKEY)

    def test_bits_acima_do_percurso_sao_ignorados(self):
        m = modulos(4)
        fraca = MerkleTree(m, leaf_hash=hash_data_sem_posicao)
        prova = make_proof(1 + 2 ** fraca.num_levels, fraca.siblings(1))
        self.assertEqual(module_hash_check(fraca.root, m[1], prova, hash_data_sem_posicao), OK)

    def test_varredura_encontra_aceitacoes_indevidas(self):
        res = varrer(5, hash_data_sem_posicao)
        self.assertEqual(res.legitimas_recusadas, 0)
        self.assertGreater(res.indevidas_aceitas, 0)


if __name__ == "__main__":
    unittest.main()
