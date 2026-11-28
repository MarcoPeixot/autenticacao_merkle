# TUF e SBAT: o que aproveitamos

Do TUF aproveitamos o controle de versões dos metadados assinados. Do SBAT, a revogação por número de geração. Ficaram de fora a expiração do TUF, que barra o congelamento, e as assinaturas com limiar mínimo (threshold), que limitam o estrago de uma chave roubada.

## TUF

A especificação do TUF (versão 1.0.37, seção 1.5.2) lista os ataques que um cliente deve barrar. Neste quadro, cada um está traduzido para o nosso verificador:

| Ataque no TUF | No nosso caso | Regra | Situação |
| --- | --- | --- | --- |
| Instalação arbitrária | Módulo que nenhuma autoridade autorizou (V1) | R2, R3 | Coberto |
| Rollback | Manifesto ou tabela de revogação mais antigos (V3) | R5, R6 | Coberto |
| Mix-and-match | Prova de uma árvore com o manifesto de outra; manifesto de outro kernel | R3 (número da árvore na folha), R2 (hash do kernel) | Coberto |
| Software errado | Módulo de outro componente; manifesto de outro kernel | R4, R2 | Coberto |
| Comprometimento de chave | Autoridade complementar corrompida | R2, R4: ela fica presa às árvores, componentes e permissões que a política deu | Parcial: sem limiar de assinaturas |
| Congelamento indefinido | Reter manifestos e tabelas novos | Nenhuma | Fora do modelo. O TUF usa expiração (seção 4.3) e o papel de timestamp (seção 5.4.4) |
| Avanço rápido | Autoridade corrompida assina a maior versão possível | Nenhuma | Negação de serviço. O TUF recupera apagando os metadados depois de trocar as chaves (seção 5.3.11) |
| Dados sem fim | Manifesto, política ou tabela enormes | Formatos com tamanho exato (`FORMATO_INVALIDO`) | Parcial: o tamanho do módulo não é limitado |
| Dependências estranhas, espelhos maliciosos | | | Não se aplica |

Uma diferença de detalhe: para os metadados de snapshot e de targets, o TUF exige que a versão bata com a anunciada no nível de cima (seções 5.5.4 e 5.6.4). Não temos esse nível acima. Por isso guardamos o hash do manifesto aceito, e outro manifesto com a mesma versão sai como `ROLLBACK`.

## SBAT

| | SBAT | Nosso verificador |
| --- | --- | --- |
| Onde está a geração | Seção `.sbat` do binário: componente, geração, fabricante | Dentro da folha, junto com o componente. A raiz assinada no manifesto cobre os dois |
| Quem atribui | O fabricante, para a geração do produto | A autoridade complementar |
| Onde fica o mínimo | Variável UEFI `SbatLevel` | Tabela assinada pela autoridade de revogação, guardada no estado |
| Só sobe? | "Both generation numbers should only ever go up" | Uma tabela que reduz um mínimo sai como `REVOGACAO_REGRESSIVA`. A versão da tabela também só sobe |
| Por que existe | A lista de revogação do UEFI (dbx) enche: só o BootHole ocupou cerca de 10 kB de 32 kB | Evitar uma assinatura ML-DSA por módulo, de 2.420 a 4.627 bytes |

O limite é o mesmo nos dois. A geração é o que o fabricante, ou a autoridade, declara. Uma autoridade corrompida pode republicar código vulnerável com uma geração nova, e a revogação por geração não pega. O documento do SBAT não trata desse caso. No nosso modelo isso está dentro dos limites da autoridade, e o que a corta é tirar a chave dela da política (achado 5 do [argumento](argumento-de-seguranca.md)).

## Fontes

- [The Update Framework Specification](https://theupdateframework.github.io/specification/latest/), versão 1.0.37, 8 out. 2026: seções 1.5.2, 4.3, 5.3.11, 5.4.4, 5.5.4 e 5.6.4.
- rhboot/shim, [SBAT.md](https://github.com/rhboot/shim/blob/main/SBAT.md): formato da seção `.sbat`, variável `SbatLevel`, gerações que só sobem e motivação pelo tamanho da dbx.
