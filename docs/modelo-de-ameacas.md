# Modelo de ameaças (MR-AUTH)

O modelo diz o que conta como ataque contra o verificador de várias raízes. Cada violação tem de virar um caso de teste, e cada regra da [especificação](../spec/README.md) tem de barrar ao menos uma violação. A ligação entre violação, regra, hipótese e teste está em [`argumento-de-seguranca.md`](argumento-de-seguranca.md).

## Participantes

| Participante | O que faz | O que tem | Pode ser corrompido? |
| --- | --- | --- | --- |
| Autoridade principal | Compila o kernel e os módulos dele | A raiz principal e o hash do kernel, embutidos na imagem (identificador 0) | Não |
| Autoridade complementar | Publica uma árvore complementar e assina com ML-DSA o manifesto de cada versão | Uma chave na política, com as árvores, componentes e permissões que pode autorizar | Sim |
| Autoridade de revogação | Assina a tabela com a geração mínima de cada componente | A chave de revogação, na política | Sim |
| Dono do sistema | Escreve a política e provisiona o estado com a primeira tabela | A política e o estado | Não |
| Verificador | Decide se aceita cada módulo e devolve decisão, raiz, autoridade e motivo (R8) | Raiz principal, hash do kernel, política e estado | Não |
| Atacante | Tenta fazer o verificador aceitar o que não devia | O que está descrito abaixo | |

O estado guarda a última tabela de revogação aceita e, para cada árvore complementar, a maior versão aceita e o SHA-256 dos 98 bytes assinados do manifesto dessa versão.

## O que é íntegro

- **I1, imagem do kernel:** a raiz principal, a profundidade dela e o hash do kernel não mudam.
- **I2, política:** chega por um canal íntegro e o atacante não a altera.
- **I3, estado:** fica num diretório sob controle do dono, e cada atualização é atômica, com trava. O protótipo simula armazenamento protegido com um arquivo comum.
- **I4, primitivas:** o SHA-256 e o ML-DSA só são atacados por busca genérica. As hipóteses de cada um estão no argumento.

## O que o atacante pode fazer

- **A1, controlar a distribuição.** Entrega ao verificador qualquer módulo, prova, manifesto, componente, geração e tabela de revogação. Pode reapresentar tudo o que já foi publicado, com as assinaturas válidas originais.
- **A2, corromper autoridades complementares.** Com a chave de uma delas, assina o que quiser.
- **A3, corromper a autoridade de revogação.** Assina qualquer tabela.
- **A4, calcular hashes.** Faz quantas consultas ao SHA-256 quiser, com computador clássico ou quântico.

O atacante não altera a imagem, a política nem o estado, e não corrompe a autoridade principal nem o dono do sistema.

## Violações

Cada violação é um evento na saída do verificador: uma decisão `OK` que não devia ter saído.

**V1, origem.** O verificador aceita o módulo `m` pela árvore `t`, com posição, componente e geração declarados, e a autoridade que a política associa a `t` é honesta e nunca publicou um manifesto de `t` cuja árvore tenha essa folha. Na árvore principal (`t = 0`), basta `m` não ser o módulo daquela posição na árvore da imagem. A troca de origem entre autoridades é um caso de V1: uma autoridade corrompida tentando passar um módulo pela árvore de outra.

**V2, permissão.** O verificador aceita `m` com as permissões pedidas no manifesto, e alguma delas não está na máscara que a política dá à autoridade de `t` para o par árvore e componente. Vale mesmo com a autoridade de `t` corrompida: é exatamente o que ela não pode fazer.

**V3, estado.** Uma de duas coisas:

- **V3a, versão:** o verificador aceita `m` pelo manifesto de versão `v` da árvore `t` depois de já ter aceitado uma versão maior que `v` para `t`, ou aceita um manifesto de versão `v` diferente do que já aceitou com essa versão;
- **V3b, revogação:** o verificador aceita `m` com componente `c` e geração `g`, sendo `g` menor que a geração mínima de `c` numa tabela que ele já aceitou.

Vale mesmo com autoridades corrompidas, inclusive a de revogação.

Uma autoridade corrompida que assina dentro dos próprios limites age como a política permite, e isso não é violação. A violação é ela se passar por outra (V1), ampliar as próprias permissões (V2) ou desfazer uma versão ou revogação já registrada (V3).

## Fora do modelo

- **Congelamento.** Reter manifestos e tabelas novos. O verificador continua aceitando a última versão que viu, e só registra uma versão quando um módulo dela é carregado.
- **O que uma autoridade assina dentro dos próprios limites**, inclusive reetiquetar código antigo com uma geração nova. A consequência está nas lacunas do argumento.
- **Negação de serviço**, como uma tabela que sobe todas as gerações mínimas ou um manifesto com a maior versão possível, que trava a árvore.
- **O carregador do kernel**, canais laterais e módulos já carregados. O protótipo roda em espaço de usuário.
