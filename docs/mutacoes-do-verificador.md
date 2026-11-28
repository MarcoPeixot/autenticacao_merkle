# Mutações do verificador em C: resultado bruto

Gerado por `python3 -m tools.mutar_verificador --gravar` (precisa de Docker). Cada linha tira uma checagem do verificador numa cópia do repositório e roda `make -C verifier test` no Debian 13. A leitura está em `docs/argumento-de-seguranca.md`.

Acusada quer dizer que algum teste percebeu a falta da checagem. Não quer dizer que o ataque passaria: às vezes outra checagem recusa com outro motivo, e a coluna da direita mostra qual.

21 de 22 mutações acusadas.

| Regra | Violação | Checagem retirada | Resultado | Primeiro caso que mudou |
| --- | --- | --- | --- | --- |
| R1, R3 | V1 | raiz não comparada no fim do caminho | acusada | vetor `n1-modulo-alterado`: esperado ENOKEY, veio OK |
| R1, R7 | V1 | tamanho da prova não conferido com a profundidade | acusada | vetor `n1-prova-truncada`: esperado ENOPKG, veio ENOKEY |
| R2 | V1 | assinatura do manifesto não conferida | acusada | `assinatura alterada`: esperado ASSINATURA_INVALIDA, veio OK |
| R2 | V1 | autorização da autoridade para a árvore não conferida | acusada | `arvore fora da politica`: esperado AUTORIDADE_NAO_AUTORIZADA, veio COMPONENTE_NAO_AUTORIZADO |
| R2 | V1 | árvore com duas autoridades aceita | acusada | `arvore com duas autoridades`: esperado AUTORIDADE_NAO_AUTORIZADA, veio OK |
| R2 | V1 | manifesto complementar com árvore 0, a da imagem, aceito na leitura | acusada | `manifesto da arvore principal`: esperado FORMATO_INVALIDO, veio AUTORIDADE_NAO_AUTORIZADA |
| R2 | V1 | hash do kernel não conferido | acusada | `kernel`: esperado KERNEL_INCOMPATIVEL, veio OK |
| R3 | V1 | folha sem o número da árvore, no C e no gerador dos testes | acusada | `prova de outra arvore`: esperado ENOKEY, veio OK |
| R4 | V2 | componente da autorização não conferido | acusada | `componente`: esperado COMPONENTE_NAO_AUTORIZADO, veio OK |
| R4 | V2 | permissões pedidas não conferidas com a máscara | acusada | `permissao`: esperado PERMISSAO_NEGADA, veio OK |
| R5 | V3 | versão menor que a aceita passa | acusada | `versao antiga`: esperado ROLLBACK, veio OK |
| R5 | V3 | outro manifesto com a versão aceita passa | acusada | `mesma versao com outro manifesto`: esperado ROLLBACK, veio OK |
| R5 | V3 | versão aceita não gravada no estado | acusada | `versao antiga`: esperado ROLLBACK, veio OK |
| R6 | V3 | geração mínima não conferida | acusada | `geracao revogada`: esperado REVOGADO, veio OK |
| R6 | V3 | assinatura da tabela inicial não conferida | acusada | `assinante errado`: esperado ASSINATURA_INVALIDA, veio OK |
| R6 | V3 | assinatura da tabela nova não conferida | acusada | `tabela de outro assinante`: esperado ASSINATURA_INVALIDA, veio OK |
| R6 | V3 | tabela com versão menor que a aceita passa | acusada | `tabela antiga com os mesmos minimos`: esperado ROLLBACK, veio OK |
| R6 | V3 | outra tabela com a versão aceita passa | acusada | `mesma versao de tabela`: esperado ROLLBACK, veio OK |
| R6 | V3 | geração mínima reduzida numa tabela nova | acusada | `diminuir minimo`: esperado REVOGACAO_REGRESSIVA, veio OK |
| R7 | V1 | profundidade do manifesto não conferida | acusada | `niveis`: esperado FORMATO_INVALIDO, veio ENOPKG |
| R7 | V1 | árvore com zero folhas não recusada de cara | sobrevive, como esperado | – |
| R7 | V1 | posição não conferida com o número de folhas | acusada | `posicao`: esperado POSICAO_INVALIDA, veio ENOKEY |

## Por que sobrevive

- **árvore com zero folhas não recusada de cara:** zero folhas pede profundidade 1 e nenhuma posição é menor que zero, então R7 recusa pela profundidade ou pela posição.
