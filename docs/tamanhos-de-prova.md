# Tamanhos de prova

Gerado por `python3 -m tools.tamanhos_de_prova --gravar`. Os tamanhos são medidos nas provas geradas pelo modelo.

| Módulos | Raízes | Módulos por árvore | Níveis | Prova por módulo (bytes) | Todas as provas (bytes) | Todas as raízes (bytes) | Assinatura ML-DSA é maior em |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 1 | 128 | 7 | 228 | 29.184 | 36 | 10,6 a 20,3 vezes |
| 128 | 4 | 32 | 5 | 164 | 20.992 | 144 | 14,8 a 28,2 vezes |
| 128 | 16 | 8 | 3 | 100 | 12.800 | 576 | 24,2 a 46,3 vezes |
| 1.024 | 1 | 1.024 | 10 | 324 | 331.776 | 36 | 7,5 a 14,3 vezes |
| 1.024 | 4 | 256 | 8 | 260 | 266.240 | 144 | 9,3 a 17,8 vezes |
| 1.024 | 16 | 64 | 6 | 196 | 200.704 | 576 | 12,3 a 23,6 vezes |
| 4.096 | 1 | 4.096 | 12 | 388 | 1.589.248 | 36 | 6,2 a 11,9 vezes |
| 4.096 | 4 | 1.024 | 10 | 324 | 1.327.104 | 144 | 7,5 a 14,3 vezes |
| 4.096 | 16 | 256 | 8 | 260 | 1.064.960 | 576 | 9,3 a 17,8 vezes |
| 8.192 | 1 | 8.192 | 13 | 420 | 3.440.640 | 36 | 5,8 a 11,0 vezes |
| 8.192 | 4 | 2.048 | 11 | 356 | 2.916.352 | 144 | 6,8 a 13,0 vezes |
| 8.192 | 16 | 512 | 9 | 292 | 2.392.064 | 576 | 8,3 a 15,8 vezes |

A prova tem 4 bytes de posição e 32 por nível. Com mais árvores cada uma fica mais baixa e a prova encurta.

Assinaturas ML-DSA para comparar (FIPS 204), em bytes: ML-DSA-44: 2.420, ML-DSA-65: 3.309, ML-DSA-87: 4.627.

Não entra na conta: o manifesto assinado de cada raiz complementar (ainda sem formato) e o rodapé de assinatura que o kernel anexa a todo módulo.
