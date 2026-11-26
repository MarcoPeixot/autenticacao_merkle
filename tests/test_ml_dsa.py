"""Partes da medição do ML-DSA que não precisam de Docker.

A medição em si (``python3 -m tools.medir_ml_dsa``) roda num container. Aqui
ficam a leitura da saída do programa, a conta da mediana e dos quartis e o que
conta como problema.
"""

import unittest

from tools.medir_ml_dsa import (
    CHECAGENS,
    FIPS_204,
    OPERACOES,
    PROGRAMA,
    ler_saida,
    mediana_e_quartis,
    relatorio,
)
from tools.tamanhos_de_prova import ML_DSA

RODADAS = 3


def saida_esperada(rodadas=RODADAS):
    """O que o programa imprime quando tudo sai como o FIPS 204 manda."""
    linhas = ["ambiente arquitetura: aarch64", "ambiente openssl: OpenSSL 3.5.9"]
    for conjunto, fips in FIPS_204.items():
        linhas.append(f"tamanho {conjunto} {fips.publica} {fips.privada} {fips.assinatura}")
        for caso, (_, esperado) in CHECAGENS.items():
            linhas.append(f"checagem {conjunto} {caso} {esperado}")
        for operacao in OPERACOES:
            linhas.append(f"tempo {conjunto} {operacao} " + " ".join(f"{10 + r}.50" for r in range(rodadas)))
    return "\n".join(linhas) + "\n"


def trocar(antes, depois):
    texto = saida_esperada()
    assert antes in texto
    return texto.replace(antes, depois)


class Fips204(unittest.TestCase):
    def test_assinaturas_iguais_as_da_tabela_de_tamanhos(self):
        self.assertEqual({c: f.assinatura for c, f in FIPS_204.items()}, ML_DSA)

    def test_programa_usa_os_mesmos_nomes(self):
        fonte = (PROGRAMA / "medir.c").read_text(encoding="utf-8")
        for nome in [*FIPS_204, *CHECAGENS, *OPERACOES]:
            with self.subTest(nome=nome):
                self.assertIn(f'"{nome}"', fonte)


class Leitura(unittest.TestCase):
    def test_le_cada_tipo_de_linha(self):
        med = ler_saida(saida_esperada() + "aviso medir.c:1:1: warning: exemplo\n")
        self.assertEqual(med.ambiente, ["arquitetura: aarch64", "openssl: OpenSSL 3.5.9"])
        self.assertEqual(med.avisos, ["medir.c:1:1: warning: exemplo"])
        self.assertEqual(med.tamanhos["ML-DSA-65"], (1952, 4032, 3309))
        self.assertEqual(med.checagens[("ML-DSA-87", "outra_chave")], "recusa")
        self.assertEqual(med.tempos[("ML-DSA-44", "verificar")], [10.5, 11.5, 12.5])

    def test_recusa_linha_desconhecida(self):
        with self.assertRaises(ValueError):
            ler_saida("qualquer coisa\n")


class Problemas(unittest.TestCase):
    def test_saida_esperada_nao_tem_problema(self):
        self.assertEqual(ler_saida(saida_esperada()).problemas(RODADAS), [])

    def test_tamanho_diferente_do_fips(self):
        texto = trocar("tamanho ML-DSA-65 1952 4032 3309", "tamanho ML-DSA-65 1952 4032 3308")
        problemas = ler_saida(texto).problemas(RODADAS)
        self.assertEqual(len(problemas), 1)
        self.assertTrue(problemas[0].startswith("ML-DSA-65"))

    def test_assinatura_alterada_aceita(self):
        texto = trocar("checagem ML-DSA-44 assinatura_alterada recusa", "checagem ML-DSA-44 assinatura_alterada aceita")
        problemas = ler_saida(texto).problemas(RODADAS)
        self.assertEqual(problemas, ["ML-DSA-44, assinatura com um bit trocado: aceita, esperado recusa"])

    def test_conjunto_que_nao_rodou(self):
        texto = "".join(linha + "\n" for linha in saida_esperada().splitlines() if "ML-DSA-87" not in linha)
        self.assertEqual(ler_saida(texto).problemas(RODADAS), ["ML-DSA-87: não mediu"])

    def test_rodada_faltando(self):
        self.assertEqual(len(ler_saida(saida_esperada(RODADAS - 1)).problemas(RODADAS)), 9)


class Estatistica(unittest.TestCase):
    def test_mediana_e_quartis(self):
        self.assertEqual(mediana_e_quartis([9, 1, 8, 2, 7, 3, 6, 4, 5]), (5, 3, 7))

    def test_um_valor_so(self):
        self.assertEqual(mediana_e_quartis([4.0]), (4.0, 4.0, 4.0))


class Relatorio(unittest.TestCase):
    def test_uma_linha_de_tamanho_e_uma_de_tempo_por_conjunto(self):
        texto = relatorio(ler_saida(saida_esperada()), RODADAS)
        for conjunto in FIPS_204:
            linhas = [l for l in texto.splitlines() if l.startswith(f"| {conjunto} |")]
            self.assertEqual(len(linhas), 2, conjunto)
        self.assertIn("| 11,5 (11,0–12,0) |", texto)
        self.assertNotIn("## Problemas", texto)

    def test_problema_aparece_destacado_e_listado(self):
        texto = trocar("checagem ML-DSA-44 outra_chave recusa", "checagem ML-DSA-44 outra_chave aceita")
        saida = relatorio(ler_saida(texto), RODADAS)
        self.assertIn("**aceita**", saida)
        self.assertIn("## Problemas", saida)


if __name__ == "__main__":
    unittest.main()
