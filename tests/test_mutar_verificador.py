"""Partes do teste de mutação do verificador em C que não precisam de Docker.

As mutações rodam com ``python3 -m tools.mutar_verificador``. Aqui fica a
conferência de que cada trecho ainda existe no código, de que as regras e
violações estão cobertas, e a leitura da saída do ``make test``.
"""

import re
import unittest

from tools.mutar_verificador import MUTACOES, RAIZ_DO_REPOSITORIO, Resultado, primeira_falha, relatorio

ESPECIFICACAO = (RAIZ_DO_REPOSITORIO / "spec" / "README.md").read_text(encoding="utf-8")


class Mutacoes(unittest.TestCase):
    def test_cada_trecho_aparece_uma_vez_no_codigo(self):
        for mutacao in MUTACOES:
            for arquivo, antes, _ in mutacao.trocas:
                with self.subTest(mutacao=mutacao.descricao, arquivo=arquivo):
                    texto = (RAIZ_DO_REPOSITORIO / arquivo).read_text(encoding="utf-8")
                    self.assertEqual(texto.count(antes), 1)

    def test_cobre_as_regras_e_as_violacoes(self):
        regras = {regra for m in MUTACOES for regra in m.regras}
        self.assertTrue({f"R{n}" for n in range(1, 8)} <= regras)
        self.assertEqual({m.violacao for m in MUTACOES}, {"V1", "V2", "V3"})

    def test_regras_existem_na_especificacao(self):
        regras_da_especificacao = set(re.findall(r"^\| (R\d) \|", ESPECIFICACAO, re.MULTILINE))
        for mutacao in MUTACOES:
            with self.subTest(mutacao=mutacao.descricao):
                self.assertTrue(set(mutacao.regras) <= regras_da_especificacao)

    def test_descricoes_unicas(self):
        descricoes = [m.descricao for m in MUTACOES]
        self.assertEqual(len(descricoes), len(set(descricoes)))


class Leitura(unittest.TestCase):
    def test_caso_de_varias_raizes(self):
        saida = (
            "Traceback (most recent call last):\n"
            "AssertionError: versao antiga: esperado ['ROLLBACK ab12 1'], veio OK ab12 1 (saída 0)\n"
        )
        self.assertEqual(primeira_falha(saida), "`versao antiga`: esperado ROLLBACK, veio OK")

    def test_caso_com_dois_motivos_aceitos(self):
        saida = "AssertionError: x: esperado ['OK - -', 'ROLLBACK - -'], veio ENOKEY - - (saída 1)\n"
        self.assertEqual(primeira_falha(saida), "`x`: esperado OK ou ROLLBACK, veio ENOKEY")

    def test_programa_que_quebrou(self):
        saida = "AssertionError: kernel: esperado ['KERNEL_INCOMPATIVEL - -'], veio  (saída -11)\n"
        self.assertEqual(primeira_falha(saida), "`kernel`: esperado KERNEL_INCOMPATIVEL, veio nada (saída -11)")

    def test_vetor_de_raiz_unica(self):
        saida = "n1-prova-truncada: C=ENOKEY, Python=ENOPKG, esperado=ENOPKG\nmake: *** [Makefile:24: test] Error 1\n"
        self.assertEqual(primeira_falha(saida), "vetor `n1-prova-truncada`: esperado ENOPKG, veio ENOKEY")

    def test_erro_de_compilacao(self):
        self.assertEqual(primeira_falha("mrauth.c:70:5: error: expected ';'\n"), "não compilou")


class Relatorio(unittest.TestCase):
    def test_sobrevivente_inesperada_aparece_como_problema(self):
        normal = next(m for m in MUTACOES if m.sobrevive_porque is None)
        texto = relatorio([Resultado(normal, False, "")])
        self.assertIn("**sobreviveu**", texto)
        self.assertIn("## Problemas", texto)

    def test_sobrevivente_esperada_nao_e_problema(self):
        esperada = next(m for m in MUTACOES if m.sobrevive_porque is not None)
        resultado = Resultado(esperada, False, "")
        self.assertIsNone(resultado.problema())
        self.assertIn("## Por que sobrevive", relatorio([resultado]))


if __name__ == "__main__":
    unittest.main()
