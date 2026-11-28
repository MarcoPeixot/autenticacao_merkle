# Hipóteses

| Hipótese | Estado |
| --- | --- |
| H1: busca multi-alvo nos nós internos | testada em 24/11/2026: não vale dentro de uma árvore, vale entre árvores |
| H2: uso indevido da posição | testada em 23/11/2026, descartada |
| H3: troca de origem entre autoridades | testada em 27/11/2026 no verificador em C, descartada |

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

O nó interno não tem nível, índice nem identificador de árvore, então um hash com prefixo `0x02` pode coincidir com qualquer nó de qualquer árvore. A proposta usou isso como pior caso: com cerca de 2^14 nós, uma segunda pré-imagem cairia de 2^256 para 2^242. Testamos se cada coincidência vira mesmo uma prova aceita.

Com SHA-256 inteiro a busca não termina, então truncamos o hash para 14 bits. O atacante calcula a folha de um módulo que não está em árvore nenhuma, declarando a posição 0 da árvore 0. A cada tentativa inventa um irmão, calcula o nó de cima e compara com todos os nós internos de todas as árvores. Quando coincide, monta a prova com os irmãos legítimos dali para cima e entrega ao verificador.

São 1.048.576 tentativas por esquema, em árvores de 64 módulos (63 nós internos cada). Com um alvo só, o esperado é 64 provas aceitas. O ganho é quantas vezes as aceitas passam disso.

| Esquema | Árvores | Nós comparados | Coincidências | Aceitas | Ganho |
| --- | ---: | ---: | ---: | ---: | ---: |
| Patch | 1 | 63 | 4.001 | 62 | 1,0 |
| Patch | 4 | 252 | 16.115 | 259 | 4,0 |
| Patch | 16 | 1.008 | 64.175 | 1.077 | 16,8 |
| Folha sem posição | 16 | 1.008 | 64.539 | 32.801 | 512,5 |
| Folha com o número da árvore | 16 | 1.008 | 64.166 | 69 | 1,1 |

- **Dentro de uma árvore não tem ganho.** As coincidências aparecem na proporção dos 63 nós, mas a prova só fecha no nó que fica acima da posição declarada. Nos outros nós do mesmo nível o verificador recalcula a folha com outra posição e o caminho não bate. Nos nós de outro nível a prova fica com o tamanho errado.
- **Entre árvores tem, e é o número de raízes.** O mesmo nó existe em cada árvore e nada na folha diz de qual árvore ela é.
- **Sem a posição na folha vale todo nó do nível**: 32 por árvore.
- **Com o número da árvore na folha o ganho some**, sem mexer nos nós internos nem no tamanho da prova.

Repetimos com o atacante construindo 2 e 3 níveis antes de comparar. O ganho continua 1, 4 e 16.

O que muda para o projeto: pela mesma conta, com 16 raízes a segunda pré-imagem clássica fica perto de 2^252, e não dos 2^242 que usamos como teto. Para a decisão entre manifesto e endereços, o custo de manter o formato do patch são 4 bits com 16 raízes, e o número da árvore na folha já bastaria para tirar isso. A especificação adotou essa folha (prefixo `0x03`).

Limites: hash truncado e busca clássica por força bruta. A conta com os limites de Hülsing, Rijneveld e Song, clássica e quântica, está em [`conta-multialvo.md`](conta-multialvo.md): com 16 raízes no formato do patch, 2^252 e cerca de 2^126; com o número da árvore na folha, 2^256 e 2^128. As árvores têm o mesmo formato de folha e a prova vale contra a raiz que indicar; manifesto e política ficaram de fora porque, como estão planejados, não entram em nenhum hash. Com 14 bits algumas provas erradas fecham por outra coincidência no caminho que o verificador recalcula (no máximo 12 por linha). Contamos à parte: conferir uma prova são hashes novos, cada um com um alvo só.

Refazer: `python3 -m tools.experimento_multialvo --gravar`. A tabela completa fica em `docs/experimento-multialvo.md`.

## H3: troca de origem

Com várias raízes aparece um ataque que a raiz única não tem. Uma autoridade, honesta ou corrompida, tenta fazer o verificador aceitar um módulo pela árvore de outra. É um caso da violação V1 do [modelo de ameaças](modelo-de-ameacas.md).

Testamos no verificador em C os seis jeitos que o formato permite:

| Tentativa | Caso de teste | Resposta |
| --- | --- | --- |
| Assinar o manifesto da árvore de outra autoridade | `autoridade fora da arvore` | `AUTORIDADE_NAO_AUTORIZADA` |
| Assinar o manifesto de uma árvore que não está na política | `arvore fora da politica` | `AUTORIDADE_NAO_AUTORIZADA` |
| Assinar com uma chave que a política não conhece | `autoridade desconhecida` | `AUTORIDADE_NAO_AUTORIZADA` |
| Aproveitar uma política que dá a mesma árvore a duas autoridades | `arvore com duas autoridades` | `AUTORIDADE_NAO_AUTORIZADA` |
| Declarar o manifesto como sendo da árvore principal | `manifesto da arvore principal` | `FORMATO_INVALIDO` |
| Apresentar a prova da própria árvore com o manifesto da outra | `prova de outra arvore` | `ENOKEY` |

Todas foram recusadas, nas duas compilações, com ML-DSA-44. Pelo teste de mutação do verificador, cada uma dessas checagens tem um teste que acusa a falta dela ([`mutacoes-do-verificador.md`](mutacoes-do-verificador.md)).

Limites: o resultado depende da política íntegra. Com a folha do patch, sem o número da árvore, a última tentativa viraria uma busca de segunda pré-imagem com ganho igual ao número de raízes (H1).

Refazer: `python3 -m tools.testar_verificador` e `python3 -m tools.mutar_verificador --gravar`. Os dois precisam de Docker.
