# Vetores de teste

Um vetor é uma entrada completa do verificador com a decisão esperada. O
modelo em Python e o verificador em C leem os mesmos arquivos e têm de dar a
mesma decisão em todos.

## `raiz-unica.json`

Cem vetores do esquema do patch, com uma única raiz: 32 aceitos, 25 recusados
pelo tamanho da prova e 43 recusados pelo caminho. As árvores têm 1, 2, 3, 5, 8
e 13 módulos, mais a raiz sem módulos.

| Campo | Tipo | O que é |
| --- | --- | --- |
| `name` | texto | Nome único do caso |
| `targets` | texto | A regra que o caso mira |
| `root.levels` | inteiro | Número de níveis da árvore |
| `root.hash` | hexadecimal, 32 bytes | Hash da raiz |
| `module` | hexadecimal | Bytes do módulo |
| `proof` | hexadecimal | Prova: 4 bytes de posição em big-endian e 32 bytes por nível |
| `expected` | texto | `OK`, `ENOPKG` ou `ENOKEY` |

`ENOPKG` é a recusa pelo tamanho da prova. `ENOKEY` é a recusa porque o
caminho recalculado não chega à raiz. A checagem de tamanho vem primeiro.

## Regenerar

O arquivo é gerado e não deve ser editado à mão:

```
python3 -m tools.gerar_vetores --gravar
```

Um teste falha se o arquivo estiver diferente do que o gerador produz.

## O que falta

Os vetores de várias raízes dependem do formato do manifesto e da política,
que ainda não foram especificados.
