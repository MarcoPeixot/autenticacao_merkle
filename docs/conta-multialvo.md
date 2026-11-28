# Conta do ataque multi-alvo

Com a folha do patch, o ataque multi-alvo ganha um fator igual ao número de raízes. Com a folha complementar da especificação, que leva o número da árvore, não ganha nada. Com 16 raízes no formato do patch, a segunda pré-imagem custa 2^252 operações clássicas e cerca de 2^126 consultas quânticas. Com a nossa folha, continua em 2^256 e 2^128, o mesmo que atacar um alvo só.

## O ataque

Só conta como ataque uma prova completa, com posição e irmãos, que o verificador aceite para um módulo que ninguém autorizou. As raízes são as dos manifestos honestos, porque forjar um manifesto é quebrar o ML-DSA (V1 no [modelo](modelo-de-ameacas.md)). Sobra achar uma prova que feche numa dessas raízes.

## Limites genéricos

Hülsing, Rijneveld e Song (2016, tabela 1) dão a chance de sucesso de um atacante que faz `q` consultas a um hash de `n` bits:

| Problema | Clássico | Quântico |
| --- | --- | --- |
| Segunda pré-imagem, um alvo (SPR) | (q + 1) / 2^n | Θ((q + 1)² / 2^n) |
| Segunda pré-imagem, uma função e `p` alvos (SM-SPR) | (q + 1)·p / 2^n | Θ((q + 1)²·p / 2^n) |
| Segunda pré-imagem, uma função diferente por alvo (MM-SPR) | (q + 1) / 2^n | Θ((q + 1)² / 2^n) |

Para ter sucesso com probabilidade constante, o atacante precisa de cerca de 2^n / p consultas clássicas e √(2^n / p) quânticas. O que importa é quantos alvos cada consulta consegue acertar de forma útil.

## Dentro de uma árvore, um alvo por consulta

Numa prova aceita, o verificador recalcula a folha com a posição `pos` declarada e sobe até a raiz, um nível por hash. Compare, de cima para baixo, o que o verificador calculou com a árvore honesta. No nível mais alto em que a entrada do hash difere da honesta e a saída coincide, o atacante achou uma segunda pré-imagem do nó honesto daquela posição: o nó do nível `ℓ` e índice `pos / 2^ℓ`, arredondado para baixo. Se nenhuma entrada difere, o módulo é o honesto e não há ataque.

O alvo de cada consulta está fixado antes dela. A posição entra no hash da folha, e o tamanho da prova é fixo (R7). Por isso, uma saída que coincida com outro nó do mesmo nível não serve: para usá-la, a posição teria de ser outra, e a folha mudaria. Um nó de outro nível exigiria outro tamanho de prova. Cada consulta tem um único alvo útil, e o caso é o de um alvo só: chance (q + 1) / 2^n no clássico.

No quântico, o raciocínio dá uma busca em que cada entrada tem um único valor de saída útil, com densidade de 2^-n soluções. Pela mesma técnica de Hülsing, Rijneveld e Song, o custo esperado é Θ((q + 1)² / 2^n). Não escrevemos essa redução formalmente: é um argumento, e fica marcado como tal no artigo.

O experimento confirma o caso clássico: com hash truncado a 14 bits e 63 nós internos como alvo, o ganho medido foi 1,0 ([`hipoteses.md`](hipoteses.md), H1).

## Entre árvores

| Folha | O que fixa o alvo | Alvos úteis por consulta | Ganho medido (16 árvores) |
| --- | --- | ---: | ---: |
| Patch: `0x01 ‖ pos ‖ módulo` | A posição | Um por árvore de mesma profundidade | 16,8 |
| Sem posição (variante do experimento) | Nada | Todos os nós do nível, em todas as árvores | 512,5 |
| Especificação: `0x03 ‖ árvore ‖ pos ‖ componente ‖ geração ‖ módulo` | Posição e árvore | Um | 1,1 |

Na folha do patch nada diz de qual árvore ela é. A mesma cadeia de hashes pode ser apresentada com o manifesto de qualquer árvore que tenha a profundidade certa. Por isso, cada consulta mira o nó daquela posição em todas as `k` árvores, e o caso vira SM-SPR com `p = k`. Com o número da árvore na folha, a cadeia só vale para a árvore escolhida antes da primeira consulta, e o caso volta a ser de um alvo só.

O teto de 2^242 da proposta tratava todos os cerca de 2^14 nós como alvo. Isso só aconteceria sem a posição na folha e sem o tamanho fixo da prova.

## Em bits (n = 256)

| Folha | Raízes | Alvos úteis | Clássico | Quântico |
| --- | ---: | ---: | ---: | ---: |
| Patch | 1 | 1 | 2^256 | 2^128 |
| Patch | 4 | 4 | 2^254 | 2^127 |
| Patch | 16 | 16 | 2^252 | 2^126 |
| Especificação, com o número da árvore | 16 | 1 | 2^256 | 2^128 |

O quântico conta consultas, como a tabela de Hülsing, Rijneveld e Song, sem custo de memória nem limite de profundidade do circuito. Os 4 bits perdidos com 16 raízes no formato do patch só pesam se o grupo escolher o ML-DSA-87. Esse conjunto está na categoria 5 do NIST (FIPS 204, seção 4), definida pela busca da chave do AES-256. Nos outros dois conjuntos, a parte de hash não é o elo mais fraco.

## Endereços nos nós compensam?

A variante com endereços troca o nó por `0x04 ‖ árvore ‖ nível ‖ índice ‖ esquerdo ‖ direito`. Cada nó passa a usar uma função diferente, que é o caso MM-SPR da tabela, e o limite deixa de depender do argumento da posição. A prova fica mais simples, mas o número é o mesmo: 2^256 e 2^128.

O custo de hash é igual. O SHA-256 processa blocos de 64 bytes, e a mensagem precisa de mais 9 bytes de preenchimento. O nó do patch tem 65 bytes (65 + 9 = 74) e o nó com endereço tem 74 (74 + 9 = 83). Os dois cabem em 2 blocos, e a prova tem o mesmo tamanho. O XMSS-T, de Hülsing, Rijneveld e Song, paga mais caro pela mesma garantia, porque deriva uma chave e uma máscara por chamada: nos slides dos autores, assinar fica cerca de 3 vezes mais lento.

Não compensa trocar a construção principal. A folha com o número da árvore já tira o ganho entre árvores. E, com o nó do patch, a subida pela árvore é a mesma da árvore principal, no construtor e no verificador. A variante fica como comparação. Se a medição da frente D confirmar tempo igual, vale citá-la no artigo como alternativa com prova mais direta.

## Fontes

- A. Hülsing, J. Rijneveld e F. Song, "Mitigating Multi-Target Attacks in Hash-based Signatures", PKC 2016, LNCS 9614, p. 387–416. [ePrint 2015/1256](https://eprint.iacr.org/2015/1256). A tabela 1 foi conferida nos [slides dos autores na PKC 2016](https://huelsing.net/wordpress/wp-content/uploads/2016/03/20160307_multi-target_pkc.pdf), slides "Results" e "Formalizing the issue". O servidor do ePrint recusou a leitura automática do PDF.
- NIST, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), 2024: seção 3.1 (SUF-CMA) e seção 4 (categorias 2, 3 e 5).
- Experimento multi-alvo: [`hipoteses.md`](hipoteses.md) (H1) e [`experimento-multialvo.md`](experimento-multialvo.md).
