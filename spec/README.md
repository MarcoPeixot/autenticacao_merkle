# Autenticação de módulos com múltiplas raízes

Versão implementada no protótipo da S3. A raiz principal segue o patch v5. As
árvores complementares têm um manifesto assinado por versão e vinculam seu
identificador à folha. O conjunto ML-DSA é escolhido na política. O formato
final da folha fica sujeito à revisão do grupo.

## Convenções

- `u8`, `u32` e `u64` são inteiros sem sinal de 1, 4 e 8 bytes em big-endian.
- `||` concatena bytes. Os campos aparecem na ordem indicada, sem preenchimento.
  Hashes SHA-256 têm 32 bytes. Marcadores como `AMMF` são quatro bytes ASCII.
  Cada objeto ocupa exatamente o comprimento definido pelos seus campos.
- Os identificadores de árvore e de autoridade usam `0` para a raiz principal.
  Cada árvore complementar tem um identificador único na política e pertence
  a uma autoridade. Os identificadores de componente são `u32` e têm o mesmo
  significado na política, na folha e na tabela de revogação.

## Árvore e prova

```text
folha principal     = SHA-256(0x01 || posição:u32 || módulo)
folha complementar  = SHA-256(0x03 || árvore:u32 || posição:u32 || componente:u32 || geração:u64 || módulo)
nó interno          = SHA-256(0x02 || hash esquerdo || hash direito)
nó com endereço     = SHA-256(0x04 || árvore:u32 || nível:u8 || índice:u32 || hash esquerdo || hash direito)
prova               = posição:u32 || hash irmão do primeiro nível || ... || hash irmão do último nível
```

A prova tem `4 + 32 × profundidade` bytes. Os bits da posição, do menos
significativo em diante, indicam se o hash atual fica à esquerda (`0`) ou à
direita (`1`) em cada nível. O construtor pareia consigo mesmo o último nó de um
nível ímpar. Uma árvore complementar tem pelo menos uma folha e profundidade
`max(1, ceil(log2(número de folhas)))`. A posição começa em zero e deve ser
menor que o número de folhas assinado no manifesto.

A raiz principal e sua profundidade vêm da configuração íntegra do protótipo,
que representa os valores embutidos no kernel. O patch verifica o tamanho da
prova e o caminho. Na árvore principal vazia, a profundidade é zero e a raiz
tem 32 bytes zero. A variante com endereços aplica-se às árvores complementares.
Nela, `nível = 0` nos pais das folhas e aumenta a cada subida. `índice` é a
posição do nó nesse nível, contada da esquerda a partir de zero. Ao verificar
uma prova, o índice no nível `n` é a posição da folha dividida por `2^(n + 1)`,
arredondada para baixo. O formato da folha e o comprimento da prova são
iguais nas duas compilações.

## Manifesto complementar

| Campo | Codificação | Valor |
| --- | --- | --- |
| Marcador | 4 bytes | `AMMF` |
| Formato | `u8` | `1` na compilação padrão e `2` na compilação com endereços |
| Árvore | `u32` | Identificador complementar |
| Autoridade | `u32` | Identificador da chave na política |
| Versão da árvore | `u64` | Positiva e crescente a cada novo manifesto da árvore |
| Kernel compatível | 32 bytes | SHA-256 dos bytes da imagem do kernel alvo |
| Número de folhas | `u32` | Maior que zero |
| Profundidade | `u8` | Calculada a partir do número de folhas |
| Raiz | 32 bytes | Hash de Merkle |
| Permissões pedidas | `u64` | Máscara de permissões solicitadas para os módulos do manifesto |
| Assinatura | Tamanho da tabela abaixo | ML-DSA sobre os 98 bytes anteriores |

O verificador busca a chave pública pelo identificador de autoridade, confere
a assinatura, consulta a autorização para a árvore e compara o hash do kernel
com o valor da configuração íntegra. A autoridade incrementa a versão ao
publicar qualquer alteração nos campos assinados.
Cada compilação exige o seu formato de manifesto complementar.

## Política local

```text
AMPO || 0x01 || conjunto:u8 || chave de revogação || número de autoridades:u32 || autoridades
autoridade = id:u32 || chave pública || número de autorizações:u32 || autorizações
autorização = árvore:u32 || componente:u32 || permissões:u64
```

O dono do sistema provisiona essa política por um canal íntegro. As autoridades
são ordenadas por identificador e as autorizações por `(árvore, componente)`.
Identificadores de autoridade e pares de autorização devem ser únicos em
suas respectivas listas. A chave de revogação é usada para verificar a tabela
de gerações mínimas. Cada bit setado no manifesto deve estar setado na máscara
da autorização para aquela árvore e aquele componente.

| Conjunto na política | Algoritmo | Chave pública bruta | Assinatura |
| --- | --- | ---: | ---: |
| `44` | ML-DSA-44 | 1.312 bytes | 2.420 bytes |
| `65` | ML-DSA-65 | 1.952 bytes | 3.309 bytes |
| `87` | ML-DSA-87 | 2.592 bytes | 4.627 bytes |

A política seleciona um conjunto para o protótipo. Manifestos e tabelas de
revogação usam ML-DSA sobre os bytes indicados, com contexto vazio.

## Revogação e estado de versões

```text
tabela = AMRV || 0x01 || versão:u64 || número de componentes:u32 || entradas || assinatura
entrada = componente:u32 || geração mínima:u64
estado = AMES || 0x01 || tamanho da tabela:u32 || tabela aceita || número de árvores:u32 || versões
versão de árvore = árvore:u32 || maior versão aceita:u64 || resumo do manifesto aceito
```

A autoridade de revogação assina todos os campos da tabela que precedem a
assinatura. As entradas são ordenadas por componente, sem duplicatas. A
versão da tabela é positiva e componentes ausentes têm geração mínima zero.
O protótipo é provisionado com uma tabela assinada inicial, que pode estar
vazia. Aceita uma tabela nova após conferir a assinatura, uma versão superior e
que nenhuma geração mínima anterior foi reduzida. A reapresentação da mesma
tabela é idempotente, inclusive com outra assinatura válida dos mesmos bytes.
Uma versão inferior, ou igual com outros campos assinados, resulta em
`ROLLBACK`. Uma geração mínima reduzida resulta em `REVOGACAO_REGRESSIVA`.

O estado é íntegro e persistente. Sua lista de versões é ordenada por árvore,
sem duplicatas. Uma árvore ausente ainda não tem versão aceita. O resumo é o
SHA-256 dos 98 bytes assinados do manifesto que levou a árvore à versão
registrada. Outro manifesto com a mesma versão resulta em `ROLLBACK`. O mesmo
manifesto com outra assinatura válida é aceito, como na tabela. O verificador
atualiza a versão de uma árvore só depois da aceitação do módulo. A aceitação
e a atualização usam o mesmo estado, com gravação atômica, para evitar que
uma verificação atrasada substitua uma versão ou tabela mais recente.
O estado guarda a tabela cuja assinatura foi conferida no provisionamento ou
na última atualização. O protótipo pressupõe que o diretório de estado e a
política estão sob controle do responsável pelo sistema.

## Regras do verificador

Na rota principal, aplicar R1 e devolver o resultado conforme R8. Na rota
complementar, verificar os formatos e comprimentos antes de ler campos. Em
seguida, aplicar R2, R5, R7, R3, R6 e R4 nessa ordem. A primeira falha determina
o motivo. Na aceitação, persistir a atualização de R5 antes de devolver R8.

| Regra | Verificação | Motivo da recusa |
| --- | --- | --- |
| R1 | Usar a raiz principal confiável e reproduzir a decisão do patch. O tamanho da prova é conferido antes do caminho. | `ENOPKG` ou `ENOKEY` |
| R2 | Verificar a assinatura do manifesto com a chave da política, a autorização da autoridade para a árvore e a compatibilidade com o kernel. Uma árvore com mais de uma autoridade na política é ambígua. | `AUTORIDADE_NAO_AUTORIZADA`, `ASSINATURA_INVALIDA` ou `KERNEL_INCOMPATIVEL` |
| R3 | Recalcular a folha da árvore identificada no manifesto e exigir que o caminho termine na raiz assinada. | `ENOKEY` |
| R4 | Exigir uma autorização para o par árvore e componente e que ela cubra todas as permissões pedidas. | `COMPONENTE_NAO_AUTORIZADO` ou `PERMISSAO_NEGADA` |
| R5 | Recusar uma versão menor que a maior já aceita para a mesma árvore, ou igual com outros campos assinados. | `ROLLBACK` |
| R6 | Exigir geração igual ou superior à mínima na tabela de revogação aceita. | `REVOGADO` |
| R7 | Na árvore complementar, conferir profundidade, tamanho da prova e posição. | `FORMATO_INVALIDO`, `ENOPKG` ou `POSICAO_INVALIDA` |
| R8 | Devolver decisão, raiz, autoridade reconhecida e motivo da recusa. | |

`FORMATO_INVALIDO` cobre entradas que não correspondem à codificação. Falhas
operacionais resultam em `ERRO_CRIPTOGRAFICO` ou `ERRO_PERSISTENCIA`. A rota
principal recebe a raiz confiável e representa a autoridade de identificador
zero. Na rota complementar, raiz e autoridade ficam ausentes até o manifesto
passar por R2. O teste diferencial usa a mesma entrada, estado inicial e
saída esperada para as duas implementações.

O modelo de ameaças está em [`docs/modelo-de-ameacas.md`](../docs/modelo-de-ameacas.md). A ligação de cada regra com as violações que ela barra, e os testes que acusam a falta dela, está em [`docs/argumento-de-seguranca.md`](../docs/argumento-de-seguranca.md).
