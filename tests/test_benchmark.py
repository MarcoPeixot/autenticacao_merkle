"""Partes do benchmark que não precisam de compilador nem de Docker.

O benchmark em si (``python3 -m tools.benchmark``) compila ``bench/medir.c`` e
roda no container. Aqui ficam a leitura da saída do medidor, o que conta como
problema, a ida e volta dos dados brutos e as contas das tabelas.
"""

import tempfile
import unittest
from pathlib import Path

from tools.benchmark import MEDIDOR, OPERACOES, configuracoes, esperado, gravar_dados, ler_saida
from tools.tabelas_benchmark import OPERACOES as COLUNAS
from tools.tabelas_benchmark import documento, ler_dados, totais

RODADAS = 3
ESCOLHA = (["padrao", "enderecos"], [128], [1, 4], [44])

# Tempo por item que a saída sintética usa para cada operação, em µs.
TEMPO = {"principal": 1.0, "caminho_complementar": 1.0, "manifesto": 50.0, "complementar": 50.0}


def saida_esperada(rodadas=RODADAS):
    """O que ``executar`` devolve quando tudo sai certo."""
    linhas = ["ambiente arquitetura: aarch64", "ambiente openssl: OpenSSL 3.5.9"]
    for config in configuracoes(*ESCOLHA):
        variante, total, raizes, _ = config
        linhas.append("config " + " ".join(map(str, config)))
        for operacao, itens in esperado(config).items():
            # A raiz principal com uma raiz só leva o dobro, para os totais terem o que comparar.
            base = TEMPO[operacao] * (2 if raizes == 1 else 1) * (1.1 if variante == "enderecos" else 1)
            linhas.append(f"casos {operacao} {itens} 4")
            linhas.append(f"tempo {operacao} " + " ".join(f"{base:.4f}" for _ in range(rodadas)))
        linhas.append("memoria 4000000 40000 2618")
    return "\n".join(linhas) + "\n"


class Medidor(unittest.TestCase):
    def test_medidor_usa_os_mesmos_nomes(self):
        fonte = MEDIDOR.read_text(encoding="utf-8")
        for operacao in OPERACOES:
            with self.subTest(operacao=operacao):
                self.assertIn(f'"{operacao}"', fonte)

    def test_tabelas_tem_uma_coluna_por_operacao(self):
        self.assertEqual(tuple(COLUNAS), OPERACOES)


class Configuracoes(unittest.TestCase):
    def test_uma_raiz_roda_uma_vez_sem_ml_dsa(self):
        self.assertEqual(
            configuracoes(["padrao"], [128], [1, 4], [44, 87]),
            [("padrao", 128, 1, 0), ("padrao", 128, 4, 44), ("padrao", 128, 4, 87)],
        )

    def test_itens_por_operacao(self):
        self.assertEqual(esperado(("padrao", 8192, 1, 0)), {"principal": 8192})
        self.assertEqual(
            esperado(("padrao", 8192, 16, 65)),
            {"principal": 512, "caminho_complementar": 7680, "manifesto": 15, "complementar": 7680},
        )


class Leitura(unittest.TestCase):
    def test_le_cada_tipo_de_linha(self):
        med = ler_saida(saida_esperada())
        config = ("padrao", 128, 4, 44)
        self.assertEqual(med.ambiente, ["arquitetura: aarch64", "openssl: OpenSSL 3.5.9"])
        self.assertEqual(med.casos[(config, "manifesto")], (3, 4))
        self.assertEqual(med.tempos[(config, "complementar")], [50.0] * RODADAS)
        self.assertEqual(med.memoria[config], (4000000, 40000, 2618))

    def test_recusa_linha_desconhecida(self):
        with self.assertRaises(ValueError):
            ler_saida("config padrao 128 1 0\nqualquer coisa\n")

    def test_recusa_medicao_sem_configuracao(self):
        with self.assertRaises(ValueError):
            ler_saida("tempo principal 1.0\n")


class Problemas(unittest.TestCase):
    def test_saida_esperada_nao_tem_problema(self):
        self.assertEqual(ler_saida(saida_esperada()).problemas(RODADAS, configuracoes(*ESCOLHA)), [])

    def test_rodada_faltando(self):
        texto = saida_esperada().replace("tempo manifesto 50.0000 50.0000 50.0000", "tempo manifesto 50.0000 50.0000", 1)
        problemas = ler_saida(texto).problemas(RODADAS, configuracoes(*ESCOLHA))
        self.assertEqual(problemas, ["padrao 128 4 44, manifesto: não tem 3 rodadas"])

    def test_itens_diferentes_do_esperado(self):
        texto = saida_esperada().replace("casos complementar 96 4", "casos complementar 95 4", 1)
        problemas = ler_saida(texto).problemas(RODADAS, configuracoes(*ESCOLHA))
        self.assertEqual(problemas, ["padrao 128 4 44, complementar: 95 itens, esperado 96"])

    def test_configuracao_faltando(self):
        problemas = ler_saida(saida_esperada()).problemas(RODADAS, configuracoes(["padrao"], [128], [16], [44]))
        self.assertIn("padrao 128 16 44: sem medição de memória", problemas)


class Tabelas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as pasta:
            gravar_dados(ler_saida(saida_esperada()), Path(pasta), "máquina de teste")
            cls.dados = ler_dados(Path(pasta))

    def test_ida_e_volta_dos_dados_brutos(self):
        self.assertEqual(self.dados.tempos[(("padrao", 128, 4, 44), "manifesto")], [50.0] * RODADAS)
        self.assertEqual(self.dados.itens[(("padrao", 128, 4, 44), "caminho_complementar")], 96)
        self.assertEqual(self.dados.memoria[("enderecos", 128, 1, 0)], (4000000, 40000, 2618))
        self.assertIn("- máquina: máquina de teste", self.dados.ambiente)

    def test_totais_do_conjunto(self):
        t = totais(self.dados, ("padrao", 128, 4, 44))
        self.assertAlmostEqual(t.patch, 128 * 2.0)  # 128 módulos contra uma raiz, 2 µs cada
        self.assertAlmostEqual(t.api_atual, 32 * 1.0 + 96 * 50.0)  # manifesto a cada módulo
        self.assertAlmostEqual(t.manifesto_uma_vez, 32 * 1.0 + 96 * 1.0 + 3 * 50.0)

    def test_documento_compara_as_variantes(self):
        texto = documento(self.dados)
        self.assertIn("| 128 | 4 | 1,00 | 1,10 | 1,10 |", texto)
        self.assertIn("## Tempo para verificar o conjunto inteiro", texto)


if __name__ == "__main__":
    unittest.main()
