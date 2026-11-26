# ML-DSA no ambiente: resultado bruto

Gerado por `python3 -m tools.medir_ml_dsa --gravar` (precisa de Docker). A leitura do resultado está no `README.md`. Tamanhos e checagens saem sempre iguais; os tempos mudam um pouco a cada execução e dependem da máquina.

Mensagem de 128 bytes. A verificação usa só a chave pública, importada dos bytes. Cada rodada cronometra um lote (50 chaves, 100 assinaturas, 200 verificações) e divide pelo tamanho do lote; antes das rodadas há uma de aquecimento, fora da conta.

## Ambiente

- arquitetura: aarch64
- compilador: gcc (Debian 14.2.0-19) 14.2.0
- openssl: OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)
- imagem: Debian GNU/Linux 13 (trixie)
- máquina: Apple M5, macOS; Docker Desktop, 10 CPUs
- avisos ao compilar `medir.c` com `-Wall -Wextra`: nenhum

## Tamanhos (bytes)

| Conjunto | Categoria do NIST | Chave pública | Chave privada | Assinatura | Igual ao FIPS 204 |
| --- | ---: | ---: | ---: | ---: | --- |
| ML-DSA-44 | 2 | 1.312 | 2.560 | 2.420 | sim |
| ML-DSA-65 | 3 | 1.952 | 4.032 | 3.309 | sim |
| ML-DSA-87 | 5 | 2.592 | 4.896 | 4.627 | sim |

## Checagens

| Caso | Esperado | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | --- | --- | --- | --- |
| Assinatura válida | aceita | aceita | aceita | aceita |
| Mensagem com um bit trocado | recusa | recusa | recusa | recusa |
| Assinatura com um bit trocado | recusa | recusa | recusa | recusa |
| Assinatura sem o último byte | recusa | recusa | recusa | recusa |
| Chave pública de outro par | recusa | recusa | recusa | recusa |

## Tempo por operação (µs)

Mediana das 30 rodadas e, entre parênteses, o primeiro e o terceiro quartil.

| Conjunto | Gerar a chave | Assinar | Verificar |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 50,0 (49,5–51,7) | 305,8 (283,2–330,8) | 57,1 (56,5–58,1) |
| ML-DSA-65 | 89,8 (88,8–90,5) | 460,4 (434,7–479,8) | 86,2 (85,2–87,7) |
| ML-DSA-87 | 123,7 (121,5–125,7) | 555,5 (537,8–592,3) | 133,8 (132,6–136,0) |
