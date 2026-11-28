# Medições

Benchmark do verificador em C, conjuntos de teste e dados brutos. É a pasta da frente D.

| Arquivo | O que é | Gerado por |
| --- | --- | --- |
| `tamanhos-de-prova.csv` | Bytes de prova por módulo nas 12 configurações | `python3 -m tools.tamanhos_de_prova --gravar` |
| `conjuntos.csv` | Bytes de provas, manifestos, política, revogação e estado, por variante, configuração e conjunto ML-DSA, com um resumo das raízes | `python3 -m tools.conjuntos --gravar` |
| `medir.c` | Medidor ligado ao verificador de `verifier/` | (código) |
| `dados/` | Dados brutos do benchmark de tempo e memória | `python3 -m tools.benchmark --gravar` |
| `conjuntos/`, `build/` | Entradas geradas e executáveis, fora do git | `tools.conjuntos --arquivos`, `tools.benchmark --local` |

Os dois CSV de tamanhos são determinísticos e entram no `reproduzir.py`. A pasta `dados/` tem a primeira rodada completa, feita no Docker em 27/11/2026, e as tabelas dela estão em `docs/benchmark.md`. Os números são preliminares: as medições só valem de vez quando o verificador em C passar nos vetores compartilhados de várias raízes, que dependem do modelo Python da frente B (marco do meio da S3).

## Conjuntos de teste

128, 1.024, 4.096 e 8.192 módulos, cada um dividido em 1, 4 e 16 árvores de mesmo tamanho. As escolhas abaixo são padrões e podem ser revistas pelo grupo.

- **Árvore 0, a principal.** Está no formato do patch, e a raiz dela vem da configuração íntegra. Com uma raiz só, o conjunto é o caso do patch.
- **Árvores 1 a R-1, as complementares.** Estão no formato de `spec/README.md`. A árvore `i` tem a autoridade `i` e o componente `i`, com versão 1, geração 1 e permissão 1. A política dá a cada autoridade só a própria árvore e o próprio componente. A tabela de revogação inicial exige geração mínima 1 de cada componente, então todo módulo é aceito.
- **Módulos.** Vêm de `ref/exemplos.py`, com índice global, e são os mesmos bytes da tabela de tamanhos de prova. Têm dezenas de bytes, então o tempo medido é o do esquema, não o do hash de um arquivo grande. Módulos do tamanho dos reais ficam para depois.
- **Variantes.** A `padrao` usa o manifesto de formato 1 e o nó do patch. A `enderecos` usa o formato 2, com árvore, nível e índice em cada nó complementar. Os tamanhos são iguais, e as raízes mudam.
- **ML-DSA.** São medidos os três conjuntos (44, 65 e 87), porque a escolha ainda está aberta.
- **Kernel compatível.** `SHA-256("kernel do benchmark")`.
- **Chaves e assinaturas.** As chaves saem de sementes fixas (`openssl genpkey -pkeyopt hexseed:…`) e a assinatura é determinística (`pkeyutl -pkeyopt deterministic:1`). As entradas saem iguais byte a byte em toda execução. São chaves de teste, não segredo.

`python3 -m tools.conjuntos --arquivos` grava as entradas em `bench/conjuntos/<variante>/<N>x<R>/`. Precisa de OpenSSL 3.5 ou mais novo, que vem da variável `OPENSSL`, do PATH ou do Homebrew. O `openssl` do macOS é o LibreSSL e não serve.

| Arquivo | Conteúdo |
| --- | --- |
| `raiz.bin` | Raiz principal: níveis em `u32` e hash |
| `kernel.bin` | Digest do kernel compatível |
| `casos.bin` | Um registro por módulo: árvore `u32`, componente `u32`, geração `u64`, tamanho `u32`, módulo, tamanho `u32`, prova |
| `ml-dsa-XX/politica.bin`, `revogacao.bin`, `manifesto-<árvore>.bin` | Metadados das árvores complementares, com R > 1 |

## Benchmark

```
python3 -m tools.benchmark                 # Debian 13 pelo Docker, resumo no terminal
python3 -m tools.benchmark --gravar        # também grava bench/dados/
python3 -m tools.tabelas_benchmark --gravar  # docs/benchmark.md, só a partir de bench/dados/
```

`tools.benchmark` faz quatro passos:

1. gera os conjuntos;
2. compila `medir.c` com o verificador, uma vez por variante (`-O2 -Wall -Wextra -Wpedantic`);
3. roda uma configuração por processo;
4. registra o ambiente: arquitetura, compilador, OpenSSL e sistema.

O ambiente oficial é o mesmo Debian 13 da comparação com o patch e da medição do ML-DSA. O repositório entra só para leitura, e tudo é gerado no `/tmp` do container.

`--local` roda na própria máquina. Serve para desenvolver: no macOS os tempos caem ao longo das rodadas, porque a frequência da CPU vai subindo. `--rodadas`, `--modulos`, `--raizes`, `--variantes` e `--ml-dsa` restringem a rodada.

### O que o medidor mede

Antes de medir, cada caso passa uma vez por cada operação e tem de ser aceito. Se algum não for, nada é medido. O estado é criado em memória com `iniciar_estado`. Uma verificação de cada árvore deixa a versão já aceita, e assim as rodadas não regravam o estado.

| Operação | O que cronometra | Por |
| --- | --- | --- |
| `principal` | `verificar_raiz_unica` | módulo da árvore principal |
| `caminho_complementar` | `verificar_prova_complementar`, só o caminho até a raiz do manifesto | módulo complementar |
| `manifesto` | Conferência ML-DSA do manifesto, como a de `verifier/mrauth.c` | árvore complementar |
| `complementar` | `verificar_complementar` inteiro, regras R2 a R8 | módulo complementar |

Cada operação tem uma passada de aquecimento e depois 30 rodadas. Uma rodada cronometra o lote inteiro, repetido até durar pelo menos 1 ms, e divide o tempo pelo número de itens. As tabelas usam a mediana e o intervalo interquartil.

A memória é o pico de memória residente de cada processo, com as entradas carregadas. No Linux ela vem do `VmHWM` de `/proc/self/status`, porque o `ru_maxrss` sobrevive ao `exec` e traria o pico do Python que chama o medidor. No macOS vem do `ru_maxrss`. Também ficam registrados os bytes das entradas e do estado. A medida inclui o processo e a libcrypto e deve ser revista com a frente C.

`verificar_complementar` confere a assinatura ML-DSA do manifesto a cada módulo. Por isso as tabelas mostram dois totais para o conjunto inteiro: com o manifesto conferido a cada módulo, como a API faz hoje, e conferido uma vez por raiz, com o caminho por módulo.

### Dados brutos

| Arquivo | Colunas |
| --- | --- |
| `dados/verificador.csv` | `variante, modulos, raizes, ml_dsa, operacao, itens, repeticoes, rodada, microssegundos` |
| `dados/memoria.csv` | `variante, modulos, raizes, ml_dsa, pico_bytes, entradas_bytes, estado_bytes` |
| `dados/ambiente.txt` | Arquitetura, compilador, OpenSSL, sistema, rodadas, avisos ao compilar e máquina |

Com uma raiz só não há ML-DSA, e `ml_dsa` fica 0.

## Falta

- Refazer a rodada completa no Docker depois que o C passar nos vetores compartilhados.
- A linha de base: uma assinatura ML-DSA por módulo.
- Rever a medida de memória com a frente C.
