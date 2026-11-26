# Comparação com o código do patch: resultado bruto

Gerado por `python3 -m tools.comparar_com_patch --gravar` (precisa de Docker). A leitura do resultado está no `README.md`.

## Arquivos do patch

| Arquivo | Hash de blob | Conferido com | Confere |
| -------------------------------------------- | -------------- | ------------------------------------ | -------- |
| `scripts/modules-merkle-tree.c` | `10e3455d5d7a` | índice do diff (arquivo novo) | sim |
| `kernel/module/hashes.c` | `3d3cf0366f75` | índice do diff (arquivo novo) | sim |
| `include/linux/module_hashes.h` | `53b34fa12f2d` | índice do diff (arquivo novo) | sim |
| `scripts/include/xalloc.h` | `8294bc0b836f` | índice do diff (depois do patch) | sim |
| `tools/include/uapi/linux/module_signature.h` | `78e206996eed` | índice do diff (depois do patch) | sim |
| `scripts/ssl-common.h` | `2db0e181143c` | Linux 4dce97c6c265 (o patch não mexe) | sim |

## Ambiente

- arquitetura: aarch64
- compilador: gcc (Debian 14.2.0-19) 14.2.0
- openssl: OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)
- imagem: Debian GNU/Linux 13 (trixie)
- avisos ao compilar a ferramenta com `-Wall -Wextra`: `patch-v5/scripts/modules-merkle-tree.c:274:36`: comparison of integer expressions of different signedness: 'unsigned int' and 'int' [-Wsign-compare]
- avisos ao compilar o verificador com `-Wall -Wextra`: nenhum

## Ferramenta de compilação

Árvores de 0, 1, 2 … 64 módulos e de 100, 127, 128, 129, 1.000, 1.023, 1.024, 1.025, 4.096, 4.230, 8.192 módulos.

| | Iguais ao modelo | Total |
| --- | ---: | ---: |
| Arquivos de raiz (`raiz.c`) | 76 | 76 |
| Arquivos de prova (`.merkle`) | 23.154 | 23.154 |

## Verificador do kernel

| Casos | Decisão esperada | Total | Kernel decidiu igual |
| --- | --- | ---: | ---: |
| Provas geradas pela ferramenta | OK | 23.154 | 23.154 |
| Vetores de `raiz-unica.json` | OK | 32 | 32 |
| Vetores de `raiz-unica.json` | ENOPKG | 25 | 25 |
| Vetores de `raiz-unica.json` | ENOKEY | 43 | 43 |

Nos 100 vetores, o kernel e o modelo deram a mesma decisão em 100.
