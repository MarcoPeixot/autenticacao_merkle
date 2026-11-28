"""Coerência entre o modelo de ameaças, a especificação e os testes do verificador.

O argumento de segurança só vale se cada regra que ele cita existe na
especificação e se cada caso de teste que ele cita existe em
``tools/testar_mrauth.py``. Estes testes conferem isso nos documentos.
"""

import re
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DOCS = RAIZ / "docs"
ESPECIFICACAO = (RAIZ / "spec" / "README.md").read_text(encoding="utf-8")
TESTES_DO_C = (RAIZ / "tools" / "testar_mrauth.py").read_text(encoding="utf-8")
VIOLACOES = {"V1", "V2", "V3"}


def ler(nome):
    return (DOCS / nome).read_text(encoding="utf-8")


def linhas_da_tabela(texto, primeira_coluna):
    """Linhas de tabela cuja primeira célula começa com ``primeira_coluna``."""
    return [l for l in texto.splitlines() if re.match(rf"^\| {primeira_coluna}", l)]


def casos_citados(texto):
    return set(re.findall(r"`([a-z][a-z ]+)`", texto))


class Argumento(unittest.TestCase):
    def setUp(self):
        self.linhas = linhas_da_tabela(ler("argumento-de-seguranca.md"), "V[123] ")

    def test_uma_linha_por_violacao(self):
        self.assertEqual({l.split()[1] for l in self.linhas}, VIOLACOES)

    def test_regras_citadas_existem_na_especificacao(self):
        regras = set(re.findall(r"^\| (R\d) \|", ESPECIFICACAO, re.MULTILINE))
        for linha in self.linhas:
            citadas = set(re.findall(r"\bR\d\b", linha))
            with self.subTest(violacao=linha.split()[1]):
                self.assertTrue(citadas)
                self.assertTrue(citadas <= regras, citadas - regras)

    def test_casos_citados_existem_nos_testes_do_c(self):
        for linha in self.linhas:
            for caso in casos_citados(linha.split("|")[4]):
                with self.subTest(caso=caso):
                    self.assertIn(f'"{caso}"', TESTES_DO_C)


class Modelo(unittest.TestCase):
    def test_define_as_tres_violacoes(self):
        texto = ler("modelo-de-ameacas.md")
        for violacao in VIOLACOES:
            with self.subTest(violacao=violacao):
                self.assertIn(f"**{violacao}, ", texto)

    def test_troca_de_origem_cita_casos_que_existem(self):
        texto = ler("hipoteses.md").split("## H3", 1)[1]
        casos = casos_citados(texto)
        self.assertGreaterEqual(len(casos), 6)
        for caso in casos:
            with self.subTest(caso=caso):
                self.assertIn(f'"{caso}"', TESTES_DO_C)


if __name__ == "__main__":
    unittest.main()
