"""Os vetores de teste gravados em ``vectors/``.

São os mesmos vetores que o verificador em C vai ler. Aqui se confere que o
arquivo está em dia com o gerador e que o modelo de referência decide como
cada vetor diz.
"""

import json
import unittest
from pathlib import Path

from ref.merkle import ENOKEY, ENOPKG, OK, Root, module_hash_check
from tools.gerar_vetores import documento

ARQUIVO = Path(__file__).resolve().parent.parent / "vectors" / "raiz-unica.json"


class Vetores(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = ARQUIVO.read_text(encoding="utf-8")
        cls.vetores = json.loads(cls.texto)["vectors"]

    def test_arquivo_esta_em_dia_com_o_gerador(self):
        self.assertEqual(self.texto, documento(), "rode: python3 -m tools.gerar_vetores --gravar")

    def test_nomes_nao_se_repetem(self):
        nomes = [v["name"] for v in self.vetores]
        self.assertEqual(len(nomes), len(set(nomes)))

    def test_ha_vetores_das_tres_decisoes(self):
        decisoes = {v["expected"] for v in self.vetores}
        self.assertEqual(decisoes, {OK, ENOPKG, ENOKEY})

    def test_modelo_decide_como_cada_vetor_diz(self):
        for v in self.vetores:
            with self.subTest(vetor=v["name"]):
                raiz = Root(v["root"]["levels"], bytes.fromhex(v["root"]["hash"]))
                decisao = module_hash_check(raiz, bytes.fromhex(v["module"]), bytes.fromhex(v["proof"]))
                self.assertEqual(decisao, v["expected"])


if __name__ == "__main__":
    unittest.main()
