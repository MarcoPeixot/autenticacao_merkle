# Hipóteses

| Hipótese | Estado |
| --- | --- |
| H1: busca multi-alvo nos nós internos | não testada |
| H2: uso indevido da posição | testada em 23/11/2026, descartada |

## H2: posição

`pos` é usado de dois jeitos no patch: os bits baixos escolhem o caminho e os 32 bits entram no hash da folha. Além disso, a raiz guarda o número de níveis mas não o de módulos, então o verificador não sabe se `pos` existe. Testamos se dá para explorar isso.

Para árvores de 1 a 32 módulos, tentamos todo módulo com toda posição de 0 a 2^(níveis+1) - 1 e com os irmãos de toda prova da árvore. Só deveria passar a posição certa com a prova certa. Rodamos o mesmo teste em uma variante sem a posição na folha.

| | Patch | Sem posição na folha |
| --- | ---: | ---: |
| Combinações | 680.764 | 680.764 |
| Aceitas indevidamente | 0 | 840 |

No patch nada passa: mudar `pos` muda o hash da folha, inclusive para posições que não existem.

Sem a posição na folha passam 840 casos:

- 528 com `pos + 2^níveis`, que faz o mesmo caminho;
- 156 por nó duplicado. Com número ímpar de nós o último é pareado com ele mesmo, e a posição espelhada passa. Com 3 módulos, o módulo 2 passa na posição 3;
- 156 com as duas coisas juntas.

Em todos é um módulo da própria árvore, com a própria prova, na posição errada.

Limites: só reaproveitamos dados legítimos (buscar colisão é a H1), a varredura completa vai até 32 módulos e tudo roda no modelo em Python.

Refazer: `python3 -m tools.experimento_posicao --gravar`. A tabela por tamanho de árvore fica em `docs/experimento-posicao.md`.

## H1: multi-alvo

Não testada ainda. O nó interno não tem nível, índice nem identificador de árvore, então um hash com prefixo `0x02` pode coincidir com qualquer nó. Com SHA-256 inteiro não dá para buscar, então a ideia é truncar o hash para poucos bits e ver se a busca contra vários nós fecha um caminho completo.
