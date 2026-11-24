"""As duas fórmulas do patch e o cálculo do número de níveis.

Os valores esperados são calculados aqui com hashlib, sem passar pelo modelo,
para que um erro no modelo não se esconda atrás dele mesmo.
"""

import hashlib
import unittest

from ref.merkle import hash_data, hash_entry, log2_roundup


def sha256(dados: bytes) -> bytes:
    return hashlib.sha256(dados).digest()


class Formulas(unittest.TestCase):
    def test_folha_e_prefixo_posicao_modulo(self):
        self.assertEqual(hash_data(0, b"abc"), sha256(b"\x01" + b"\x00\x00\x00\x00" + b"abc"))
        self.assertEqual(hash_data(5, b""), sha256(b"\x01\x00\x00\x00\x05"))

    def test_posicao_entra_em_32_bits_big_endian(self):
        self.assertEqual(hash_data(0x01020304, b"x"), sha256(b"\x01" + b"\x01\x02\x03\x04" + b"x"))
        self.assertEqual(hash_data(0xFFFFFFFF, b"x"), sha256(b"\x01" + b"\xff\xff\xff\xff" + b"x"))

    def test_no_interno_e_prefixo_esquerdo_direito(self):
        esq, dir_ = sha256(b"esquerdo"), sha256(b"direito")
        self.assertEqual(hash_entry(esq, dir_), sha256(b"\x02" + esq + dir_))

    def test_ordem_dos_filhos_importa(self):
        esq, dir_ = sha256(b"esquerdo"), sha256(b"direito")
        self.assertNotEqual(hash_entry(esq, dir_), hash_entry(dir_, esq))

    def test_folha_e_no_nao_se_confundem(self):
        # Os mesmos 64 bytes apresentados como folha e como nó interno dão
        # hashes diferentes, porque o prefixo muda.
        esq, dir_ = sha256(b"esquerdo"), sha256(b"direito")
        pos = int.from_bytes(esq[:4], "big")
        self.assertNotEqual(hash_data(pos, esq[4:] + dir_), hash_entry(esq, dir_))


class Niveis(unittest.TestCase):
    def test_log2_roundup(self):
        esperado = {
            0: 1, 1: 1, 2: 1, 3: 2, 4: 2, 5: 3, 8: 3, 9: 4,
            128: 7, 1024: 10, 4096: 12, 4230: 13, 8192: 13, 8193: 14,
        }
        for folhas, niveis in esperado.items():
            with self.subTest(folhas=folhas):
                self.assertEqual(log2_roundup(folhas), niveis)


if __name__ == "__main__":
    unittest.main()
