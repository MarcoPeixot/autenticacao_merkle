"""Provas das árvores complementares que os testes do verificador em C usam.

Os testes do C (``python3 -m tools.testar_verificador``) precisam de Docker.
Aqui fica só a montagem das provas em ``tools/testar_mrauth.py``, que roda em
qualquer lugar.
"""

import hashlib
import struct
import unittest

from tools.testar_mrauth import montar_prova

from .modulos import modulos


class ProvaComplementar(unittest.TestCase):
    def test_profundidade_igual_a_da_especificacao(self):
        # max(1, ceil(log2(folhas))), nos dois formatos de manifesto
        for formato in (1, 2):
            for folhas in range(1, 10):
                with self.subTest(formato=formato, folhas=folhas):
                    _, niveis, prova = montar_prova(7, 42, 2, formato, modulos(folhas))
                    esperado = max(1, (folhas - 1).bit_length())
                    self.assertEqual(niveis, esperado)
                    self.assertEqual(len(prova), 4 + 32 * esperado)

    def test_uma_folha_com_enderecos_conferida_na_mao(self):
        folha = hashlib.sha256(struct.pack(">BIIIQ", 3, 7, 0, 42, 2) + b"unico").digest()
        raiz = hashlib.sha256(struct.pack(">BIBI", 4, 7, 0, 0) + folha + folha).digest()
        self.assertEqual(montar_prova(7, 42, 2, 2, (b"unico",)), (raiz, 1, bytes(4) + folha))


if __name__ == "__main__":
    unittest.main()
