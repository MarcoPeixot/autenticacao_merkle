# Argumento de segurança

As três violações do [modelo MR-AUTH](modelo-de-ameacas.md) são barradas por regras da [especificação](../spec/README.md). O argumento depende de duas hipóteses sobre as primitivas: o ML-DSA não é forjável e o SHA-256 resiste a segunda pré-imagem e a colisão. Cada violação tem casos de teste no verificador em C. Em 22 checagens retiradas uma por vez, 21 foram acusadas por algum teste, e a que sobrevive é redundante de propósito.

## Violação, regra, hipótese e teste

| Violação | Regras | Hipóteses | Casos de teste (`tools/testar_mrauth.py`) |
| --- | --- | --- | --- |
| V1 origem | R1, R2, R3, R7 | ML-DSA não forjável; segunda pré-imagem do SHA-256 com um alvo útil por consulta; I1 e I2 | `assinatura alterada`, `assinatura truncada`, `autoridade desconhecida`, `autoridade fora da arvore`, `arvore fora da politica`, `arvore com duas autoridades`, `manifesto da arvore principal`, `kernel`, `formato de manifesto`, `prova de outra arvore`, `modulo alterado`, `geracao divergente`, `prova curta`, `posicao`, `niveis`, `arvore complementar vazia` |
| V2 permissão | R4, com R2 | ML-DSA não forjável; I2 | `permissao`, `componente` |
| V3 estado | R5, R6 e a atualização da tabela | ML-DSA não forjável; colisão do SHA-256 (hash do manifesto); I3 | `versao antiga`, `mesma versao com outro manifesto`, `mesma versao reassinada`, `recusa preserva versao`, `estado depois de concorrencia`, `geracao revogada`, `assinante errado`, `tabela de outro assinante`, `tabela antiga com os mesmos minimos`, `tabela antiga`, `mesma versao de tabela`, `diminuir minimo` |

Na árvore principal (R1), os 100 vetores de `vectors/raiz-unica.json` dão a mesma decisão no C, no Python e no código do próprio patch.

## Hipóteses sobre as primitivas

- **ML-DSA:** é projetado para ser fortemente não forjável sob ataque de mensagem escolhida (SUF-CMA, FIPS 204, seção 3.1). Usamos menos que isso, só a não forjabilidade comum (EUF-CMA): o verificador aceita os mesmos bytes com outra assinatura válida. O contexto é vazio, o padrão da seção 5.2. A política escolhe o conjunto, nas categorias 2, 3 ou 5 (seção 4).
- **SHA-256, segunda pré-imagem:** sustenta a prova (V1). Pela [conta do multi-alvo](conta-multialvo.md), com a folha que leva o número da árvore cada consulta tem um único alvo útil: 2^256 operações clássicas ou cerca de 2^128 consultas quânticas.
- **SHA-256, colisão:** sustenta o hash do manifesto guardado no estado (V3a). Os prefixos `0x01` e `0x03` (folhas) e `0x02` e `0x04` (nós) separam os domínios, e uma folha nunca vale como nó.

## Por que cada violação não acontece

**V1, origem.** Suponha que o verificador aceita o módulo `m` pela árvore `t`, e que a autoridade `a` que a política associa a `t` é honesta.

1. Pela R2, o manifesto tem assinatura válida da chave de `a`. A política autoriza `a` para `t`, e `t` não tem outra autoridade. Logo, ou `a` assinou o manifesto, ou o atacante forjou uma assinatura de ML-DSA. Raiz, profundidade e número de folhas são os que `a` publicou.
2. O leitor do manifesto recusa árvore 0 e autoridade 0, então nenhuma árvore complementar se passa pela principal (caso `manifesto da arvore principal`).
3. Pela R7, a prova tem 4 + 32 × profundidade bytes, e a posição é menor que o número de folhas.
4. Pela R3, o caminho que começa em `SHA-256(0x03 ‖ t ‖ pos ‖ componente ‖ geração ‖ m)` termina na raiz assinada. Se essa folha não é a que `a` pôs naquela posição, em algum nível o hash coincide com o do nó honesto a partir de outra entrada. Isso é uma segunda pré-imagem do SHA-256 para um nó fixado pela posição e pela árvore.

Na árvore principal, o argumento é o mesmo com a R1, a raiz da imagem (I1) e a folha `0x01`. A troca de origem também cai aqui: uma autoridade corrompida não é autorizada para `t` (R2), e a prova da árvore dela não fecha na raiz de `t`, porque a folha leva o número da árvore (R3).

**V2, permissão.** Pela R2, o campo de permissões é o que `a` assinou, ou houve forjamento. Pela R4, existe uma autorização para o par árvore e componente, e as permissões pedidas cabem na máscara dela. Com a política íntegra (I2), aceitar uma permissão fora da máscara exige forjar um manifesto. Isso vale também para `a` corrompida: ela assina o que quiser, mas a máscara não depende dela.

**V3a, versão.** O estado guarda, para cada árvore, a maior versão aceita e o SHA-256 do manifesto dela. A R5 recusa versão menor, e recusa versão igual com outro hash. Aceitar um manifesto diferente com a mesma versão exige achar outro manifesto com o mesmo SHA-256: uma colisão. A atualização acontece sob trava e por renomeação atômica (I3). Duas verificações ao mesmo tempo não fazem a versão voltar (caso `estado depois de concorrencia`).

**V3b, revogação.** A R6 compara a geração da folha com a mínima da tabela aceita. A geração está dentro da folha, então declarar outra muda o caminho (caso `geracao divergente`). Uma tabela nova só é aceita se:

- tiver a assinatura da chave de revogação;
- tiver versão maior que a atual (ou for a mesma tabela);
- não reduzir nenhuma geração mínima.

Por isso, mesmo com a chave de revogação corrompida (A3), a geração mínima de um componente nunca desce. Ela só desceria com o estado adulterado, o que I3 exclui.

## Mutações

[`mutacoes-do-verificador.md`](mutacoes-do-verificador.md) tira uma checagem do verificador por vez e roda os testes. As 22 checagens cobrem as regras de R1 a R7 e as três violações:

- 21 foram acusadas por algum teste;
- 5 delas foram acusadas com outro motivo, porque outra checagem também recusa o caso: tamanho da prova, autorização para a árvore, árvore 0, profundidade e posição. São defesas em profundidade;
- a única que sobrevive é a de zero folhas, redundante porque a profundidade e a posição já recusam.

Na primeira rodada, duas checagens sobreviveram sem explicação. Ganharam testes (achados 2 e 3 abaixo).

## Revisão da especificação contra o modelo

| # | Achado | Regra | Situação |
| ---: | --- | --- | --- |
| 1 | Um manifesto diferente com a mesma versão era aceito | R5 | Corrigido em 27/11: o estado guarda o hash do manifesto aceito |
| 2 | Nenhum teste recusava uma árvore sem dono na política. O caso `autoridade fora da arvore` era recusado pela checagem de árvore ambígua, e não pela de autorização | R2 | Teste novo, `arvore fora da politica`, achado pelas mutações |
| 3 | `revogar` não tinha teste de assinatura nem de tabela mais antiga com os mesmos mínimos | Atualização da tabela | Testes novos, `tabela de outro assinante` e `tabela antiga com os mesmos minimos`, achados pelas mutações |
| 4 | Congelamento: a versão só sobe quando um módulo da versão nova é carregado. Retendo o manifesto novo, o antigo continua aceito | R5 | Fora do modelo, como na proposta. Aberto para o grupo: registrar a versão ao instalar o manifesto, ou usar expiração com relógio confiável, como o TUF |
| 5 | Reetiquetar código antigo: uma autoridade corrompida pode republicar um binário vulnerável com geração acima da mínima | R6 | Dentro do modelo, porque ela age nos próprios limites. O que corta a autoridade é tirar a chave dela da política. O SBAT tem o mesmo limite |
| 6 | Avanço rápido: uma autoridade corrompida assina a maior versão possível e trava a árvore | R5 | Negação de serviço, fora do modelo. O dono reprovisiona o estado |
| 7 | Uma autoridade de revogação corrompida só consegue subir mínimos | Atualização da tabela | V3b continua valendo. Subir tudo é negação de serviço |
| 8 | A árvore com zero folhas é recusada também pela profundidade e pela posição | R7 | Mantida como defesa. A mutação sobrevive, como esperado |

## O que não está provado

- O caso quântico do multi-alvo é um argumento, não uma redução escrita.
- A comparação com o TUF e o SBAT está em [`tuf-e-sbat.md`](tuf-e-sbat.md).
- As hipóteses I1 a I3 não são testadas: o protótipo guarda política e estado em arquivos comuns.
