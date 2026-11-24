"""Construção da árvore e das provas, incluindo os casos de borda."""

import random
import struct
import unittest

from ref.merkle import (
    EMPTY_ROOT,
    ENOKEY,
    ENOPKG,
    OK,
    MerkleTree,
    Root,
    hash_data,
    hash_entry,
    log2_roundup,
    module_hash_check,
    proof_size,
)

from .modulos import modulos


class ArvoresPequenas(unittest.TestCase):
    """Raízes escritas à mão, nível por nível."""

    def test_um_modulo_e_pareado_consigo_mesmo(self):
        m = modulos(1)
        f0 = hash_data(0, m[0])
        self.assertEqual(MerkleTree(m).root, Root(1, hash_entry(f0, f0)))

    def test_dois_modulos(self):
        m = modulos(2)
        f0, f1 = hash_data(0, m[0]), hash_data(1, m[1])
        self.assertEqual(MerkleTree(m).root, Root(1, hash_entry(f0, f1)))

    def test_tres_modulos(self):
        m = modulos(3)
        f = [hash_data(i, m[i]) for i in range(3)]
        raiz = hash_entry(hash_entry(f[0], f[1]), hash_entry(f[2], f[2]))
        self.assertEqual(MerkleTree(m).root, Root(2, raiz))

    def test_cinco_modulos(self):
        m = modulos(5)
        f = [hash_data(i, m[i]) for i in range(5)]
        n01, n23, n44 = hash_entry(f[0], f[1]), hash_entry(f[2], f[3]), hash_entry(f[4], f[4])
        raiz = hash_entry(hash_entry(n01, n23), hash_entry(n44, n44))
        self.assertEqual(MerkleTree(m).root, Root(3, raiz))

    def test_mudar_um_modulo_muda_a_raiz(self):
        m = modulos(8)
        outra = list(m)
        outra[3] = outra[3] + b"!"
        self.assertNotEqual(MerkleTree(m).root.hash, MerkleTree(outra).root.hash)

    def test_trocar_dois_modulos_de_lugar_muda_a_raiz(self):
        m = modulos(8)
        outra = list(m)
        outra[2], outra[5] = outra[5], outra[2]
        self.assertNotEqual(MerkleTree(m).root.hash, MerkleTree(outra).root.hash)


class Provas(unittest.TestCase):
    TAMANHOS = list(range(1, 41)) + [127, 128, 129, 1000]

    def test_numero_de_niveis(self):
        for n in self.TAMANHOS:
            with self.subTest(n=n):
                self.assertEqual(MerkleTree(modulos(n)).num_levels, log2_roundup(n))

    def test_tamanho_da_prova_e_4_mais_32_por_nivel(self):
        for n in self.TAMANHOS:
            arvore = MerkleTree(modulos(n))
            for i in (0, n // 2, n - 1):
                with self.subTest(n=n, i=i):
                    self.assertEqual(len(arvore.proof(i)), 4 + 32 * arvore.num_levels)
                    self.assertEqual(len(arvore.proof(i)), proof_size(arvore.num_levels))

    def test_prova_comeca_pela_posicao(self):
        arvore = MerkleTree(modulos(13))
        for i in range(13):
            with self.subTest(i=i):
                self.assertEqual(arvore.proof(i)[:4], struct.pack(">I", i))

    def test_toda_prova_legitima_e_aceita(self):
        for n in self.TAMANHOS:
            m = modulos(n)
            arvore = MerkleTree(m)
            raiz = arvore.root
            for i in range(n):
                with self.subTest(n=n, i=i):
                    self.assertEqual(module_hash_check(raiz, m[i], arvore.proof(i)), OK)

    def test_ultima_folha_sem_par_e_irma_de_si_mesma(self):
        arvore = MerkleTree(modulos(3))
        self.assertEqual(arvore.siblings(2)[0], arvore.leaves[2])

    def test_no_interno_sem_par_e_irmao_de_si_mesmo(self):
        arvore = MerkleTree(modulos(5))
        irmaos = arvore.siblings(4)
        self.assertEqual(irmaos[0], arvore.leaves[4])
        self.assertEqual(irmaos[1], arvore.level_hashes[0][2])
        self.assertEqual(irmaos[2], arvore.level_hashes[1][0])

    def test_posicao_inexistente_nao_tem_prova(self):
        arvore = MerkleTree(modulos(5))
        for i in (-1, 5, 8):
            with self.subTest(i=i):
                with self.assertRaises(IndexError):
                    arvore.proof(i)


class ArvoreVazia(unittest.TestCase):
    def test_nao_se_constroi_arvore_sem_modulos(self):
        with self.assertRaises(ValueError):
            MerkleTree([])

    def test_raiz_vazia_recusa_qualquer_modulo(self):
        # Com zero níveis a prova tem só os 4 bytes da posição.
        self.assertEqual(module_hash_check(EMPTY_ROOT, b"qualquer", struct.pack(">I", 0)), ENOKEY)
        self.assertEqual(module_hash_check(EMPTY_ROOT, b"", struct.pack(">I", 0)), ENOKEY)

    def test_raiz_vazia_confere_o_tamanho_antes(self):
        prova_de_um_nivel = MerkleTree(modulos(2)).proof(0)
        self.assertEqual(module_hash_check(EMPTY_ROOT, b"qualquer", prova_de_um_nivel), ENOPKG)


class Aleatorio(unittest.TestCase):
    def test_arvores_aleatorias_com_semente_fixa(self):
        sorteio = random.Random(20261123)
        for _ in range(25):
            n = sorteio.randint(1, 300)
            m = [sorteio.randbytes(sorteio.randint(0, 200)) for _ in range(n)]
            arvore = MerkleTree(m)
            raiz = arvore.root
            for i in range(n):
                self.assertEqual(module_hash_check(raiz, m[i], arvore.proof(i)), OK, (n, i))


if __name__ == "__main__":
    unittest.main()
