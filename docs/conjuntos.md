# Conjuntos de teste: tamanhos

Gerado por `python3 -m tools.conjuntos --gravar`. Os tamanhos são os dos bytes montados no formato de `spec/README.md`, com as assinaturas do tamanho do FIPS 204. Os dados por configuração, com as duas variantes e um resumo das raízes, estão em `bench/conjuntos.csv`.

Cada conjunto é dividido em árvores de mesmo tamanho. A árvore 0 é a principal, no formato do patch. As outras são complementares, cada uma com a sua autoridade, um componente e um manifesto. A variante com endereços nos nós tem os mesmos tamanhos.

## Metadados das árvores complementares (bytes)

Não dependem do número de módulos, só do número de raízes e do conjunto ML-DSA. Os manifestos acompanham os módulos. A política é provisionada pelo dono do sistema, e o estado fica com o verificador. Com uma raiz só, que é o caso do patch, não há nenhum deles.

| Raízes | ML-DSA | Manifesto (cada) | Todos os manifestos | Política | Tabela de revogação | Estado |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 44 | 2.518 | 7.554 | 5.330 | 2.473 | 2.618 |
| 4 | 65 | 3.407 | 10.221 | 7.890 | 3.362 | 3.507 |
| 4 | 87 | 4.725 | 14.175 | 10.450 | 4.680 | 4.825 |
| 16 | 44 | 2.518 | 37.770 | 21.362 | 2.617 | 3.290 |
| 16 | 65 | 3.407 | 51.105 | 31.602 | 3.506 | 4.179 |
| 16 | 87 | 4.725 | 70.875 | 41.842 | 4.824 | 5.497 |

## Bytes por módulo

A prova de cada módulo mais a parte dele nos manifestos (todos os manifestos divididos pelo número de módulos).

| Módulos | Raízes | Prova | Com manifestos, ML-DSA-44 | Com manifestos, ML-DSA-65 | Com manifestos, ML-DSA-87 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 1 | 228 | 228,0 | 228,0 | 228,0 |
| 128 | 4 | 164 | 223,0 | 243,9 | 274,7 |
| 128 | 16 | 100 | 395,1 | 499,3 | 653,7 |
| 1.024 | 1 | 324 | 324,0 | 324,0 | 324,0 |
| 1.024 | 4 | 260 | 267,4 | 270,0 | 273,8 |
| 1.024 | 16 | 196 | 232,9 | 245,9 | 265,2 |
| 4.096 | 1 | 388 | 388,0 | 388,0 | 388,0 |
| 4.096 | 4 | 324 | 325,8 | 326,5 | 327,5 |
| 4.096 | 16 | 260 | 269,2 | 272,5 | 277,3 |
| 8.192 | 1 | 420 | 420,0 | 420,0 | 420,0 |
| 8.192 | 4 | 356 | 356,9 | 357,2 | 357,7 |
| 8.192 | 16 | 292 | 296,6 | 298,2 | 300,7 |

Para comparar, uma assinatura ML-DSA por módulo (FIPS 204), em bytes: ML-DSA-44: 2.420, ML-DSA-65: 3.309, ML-DSA-87: 4.627.
