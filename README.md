# Autenticação de módulos do kernel Linux com múltiplas raízes de Merkle

Trabalho de Tópicos Avançados de Criptografia.

Marco Peixoto, Wildisley Filho, Giovanna Britto, Leonardo Fischel. Orientador: Bryan Ferreira.

## Ideia

O [patch v5 do Weißschuh](https://lkml.iu.edu/2605.0/04798.html) autentica módulos do kernel com uma árvore de Merkle em vez de assinar um por um. A raiz vai dentro da imagem do kernel, então só vale para o que foi compilado junto.

```
folha = SHA-256(0x01 || posição || módulo)
nó    = SHA-256(0x02 || esquerdo || direito)
prova = posição (4 bytes) + um hash irmão por nível (32 bytes cada)
```

Queremos estender isso para módulos compilados depois (driver da NVIDIA, ZFS via DKMS), usando outras árvores, cada uma com sua raiz e sua autoridade.

## Primeira entrega (23/11/2026)

Ficou pronto o esquema de raiz única, igual ao do patch. Múltiplas raízes ainda não.

1. **Modelo em Python** (`ref/merkle.py`). Lemos `kernel/module/hashes.c` e `scripts/modules-merkle-tree.c` e reescrevemos a construção da árvore, a geração da prova e a verificação. As funções têm o mesmo nome das do patch, para conferir lado a lado.
2. **Testes** (`tests/`). São 45: as duas fórmulas de hash, árvores pequenas conferidas na mão, quantidade ímpar de módulos, árvore vazia e tudo que o verificador tem que recusar (módulo alterado, prova cortada ou comprida demais, irmão trocado, prova de outro módulo, raiz errada).
3. **Teste dos testes** (`tools/mutacoes.py`). Quebramos o modelo de 8 jeitos, um por vez, para ver se os testes percebem.
4. **Primeira hipótese de ataque** (`docs/hipoteses.md`). Testamos se dá para abusar do campo de posição da prova.
5. **Tamanho da prova** (`docs/tamanhos-de-prova.md`). Medimos nas 12 configurações da proposta.
6. **Vetores de teste** (`vectors/raiz-unica.json`). São 100 casos com entrada e resposta esperada, que o verificador em C vai usar depois.

## Segunda entrega (24/11/2026)

Testamos a hipótese que faltava, a multi-alvo. Agora as duas têm veredito.

1. **Experimento** (`tools/experimento_multialvo.py`). Busca com o hash truncado a 14 bits contra todos os nós internos, em 1, 4 e 16 árvores e em três formatos de folha.
2. **Modelo** (`ref/merkle.py`, `ref/variantes.py`). A árvore e o verificador passaram a aceitar outro hash de nó, para o mesmo código rodar com hash truncado. Entraram duas variantes: hash truncado e folha com o número da árvore.
3. **Testes** (`tests/test_multialvo.py`). Mais 15, agora são 60.
4. **Registro** (`docs/hipoteses.md`). O que testamos, o resultado e os limites.

## Terceira entrega (25/11/2026)

Rodamos o código do próprio patch num container Linux e comparamos com o modelo. Até aqui a conferência tinha sido só lendo o código.

1. **Código do patch** (`patch-v5/`). Os arquivos de que a ferramenta e o verificador precisam, sem nenhuma alteração. Cada um bate com o hash de blob do diff.
2. **Comparação** (`tools/comparar_com_patch.py`). Compila a ferramenta de compilação e o verificador do kernel num Debian 13 pelo Docker, gera as mesmas árvores do modelo e compara byte a byte.
3. **Apoio** (`tools/patch_no_linux/`). Para o `hashes.c` compilar fora do kernel, trocamos o SHA-256, as macros e os códigos de erro do kernel pelos equivalentes em espaço de usuário. O `hashes.c` não muda.
4. **Testes** (`tests/test_comparacao_com_patch.py`). Mais 6, agora são 66. Um deles confere os arquivos de `patch-v5/` a cada rodada.

## Quarta entrega (25/11/2026)

Conferimos que o ambiente tem ML-DSA, que é o que vai assinar os manifestos, e medimos os três conjuntos do FIPS 204.

1. **Medição** (`tools/ml_dsa/medir.c`, `tools/medir_ml_dsa.py`). Roda no mesmo Debian 13 da comparação. Gera as chaves, confere os tamanhos com o FIPS 204, confere que assinatura alterada não passa e mede o tempo de gerar a chave, assinar e verificar.
2. **Testes** (`tests/test_ml_dsa.py`). Mais 13, agora são 79.
3. **Resultado** (`docs/ml-dsa.md`).

## Resultados

### Testes

81 de 81 passando, em Python 3.9 e 3.15. No teste de mutação os testes pegaram os 8 defeitos.

### Comparação com o código do patch: igual

| | Iguais | Total |
| ------------------------------------------------------------ | ---------: | ---------: |
| Raízes geradas pela ferramenta do patch | 76 | 76 |
| Provas geradas pela ferramenta do patch | 23.154 | 23.154 |
| Provas da ferramenta aceitas pelo verificador do kernel | 23.154 | 23.154 |
| Vetores em que o verificador do kernel decide como esperado | 100 | 100 |

As árvores vão de 0 a 64 módulos e depois de 100 a 8.192, passando pelas bordas das potências de 2 e pelos 4.230 módulos do kernel do Debian 13.

Para ver se a comparação acusa erro, rodamos também com o modelo gravando a posição em little-endian: 74 das 76 raízes saíram diferentes.

Rodou em Linux aarch64. Não testamos em x86_64.

### Hipótese da posição: descartada

Tentamos todo módulo com toda posição e com os irmãos de toda prova, em árvores de 1 a 32 módulos. Só deveria passar a posição certa com a prova certa.

| | Patch | Sem posição na folha |
| --- | ---: | ---: |
| Combinações testadas | 680.764 | 680.764 |
| Aceitas indevidamente | 0 | 840 |

No patch nada passa, porque a posição entra no hash da folha. Tirando a posição da folha, o mesmo módulo passa em posições erradas: com 3 módulos, o módulo 2 passa também na posição 3.

O teste só reaproveita provas e módulos legítimos. Buscar colisão é a outra hipótese, a multi-alvo.

### Hipótese multi-alvo: só vale entre árvores

O nó interno não diz de que nível, índice ou árvore ele é. Na proposta usamos como pior caso que um hash do atacante valesse contra todos os nós, cerca de 2^14, o que levaria uma segunda pré-imagem de 2^256 para 2^242.

Truncamos o hash para 14 bits e deixamos o atacante comparar cada tentativa com todos os nós internos de todas as árvores (64 módulos por árvore, 1.048.576 tentativas). Com um alvo só, o esperado é 64 provas aceitas.

| Formato da folha | Árvores | Nós comparados | Coincidências | Provas aceitas | Ganho |
| ------------------------- | --------: | --------------: | --------------: | --------------: | ------: |
| Patch | 1 | 63 | 4.001 | 62 | 1,0 |
| Patch | 4 | 252 | 16.115 | 259 | 4,0 |
| Patch | 16 | 1.008 | 64.175 | 1.077 | 16,8 |
| Sem posição | 16 | 1.008 | 64.539 | 32.801 | 512,5 |
| Com o número da árvore | 16 | 1.008 | 64.166 | 69 | 1,1 |

Dentro de uma árvore o atacante não ganha nada: a coincidência aparece, mas a prova só fecha no nó que fica acima da posição declarada. Entre árvores ganha, e o ganho é o número de raízes. Com 16 raízes são 4 bits, perto de 2^252, e não 2^242.

Colocar o número da árvore na folha tira esse ganho sem mudar os nós internos nem o tamanho da prova.

Vale para busca clássica com hash truncado. A conta quântica ainda falta.

### Tamanho da prova

Bytes de prova por módulo:

| Módulos | 1 raiz | 4 raízes | 16 raízes |
| ---: | ---: | ---: | ---: |
| 128 | 228 | 164 | 100 |
| 1.024 | 324 | 260 | 196 |
| 4.096 | 388 | 324 | 260 |
| 8.192 | 420 | 356 | 292 |

A assinatura ML-DSA mais curta (ML-DSA-44) tem 2.420 bytes, 5,8 vezes a maior prova da tabela. A ML-DSA-65 tem 3.309 e a ML-DSA-87 tem 4.627.

Falta somar o manifesto assinado de cada raiz extra, que ainda não tem formato definido.

### ML-DSA no ambiente: os três conjuntos funcionam

O OpenSSL 3.5.9 do Debian 13 tem ML-DSA-44, 65 e 87. Nos três, os tamanhos batem com o FIPS 204 e a assinatura válida passa. Mensagem alterada, assinatura alterada, assinatura cortada e chave de outro par não passam.

| Conjunto | Categoria do NIST | Chave pública (bytes) | Assinatura (bytes) | Assinar (µs) | Verificar (µs) |
| -------------- | ----------: | -------------: | -------------: | -----------: | -----------: |
| ML-DSA-44 | 2 | 1.312 | 2.420 | 306 | 57 |
| ML-DSA-65 | 3 | 1.952 | 3.309 | 460 | 86 |
| ML-DSA-87 | 5 | 2.592 | 4.627 | 556 | 134 |

Os tempos são a mediana de 30 rodadas, com uma mensagem de 128 bytes. Os quartis estão em `docs/ml-dsa.md`.

Para o kernel o que pesa é verificar. Se cada raiz extra tiver um manifesto verificado uma vez, 16 raízes com ML-DSA-87 somam uns 2 ms. Assinar fica com a autoridade, fora da máquina, e varia mais porque o ML-DSA repete uma etapa interna um número aleatório de vezes.

Qual conjunto usar ainda é decisão do grupo. Estes números entram nela.

Os tempos são de um Apple M5 rodando Linux aarch64 no Docker. Servem para comparar os conjuntos entre si, não como valor absoluto. Não medimos em x86_64.

O `openssl` que vem no macOS é o LibreSSL 3.3.6, que não tem ML-DSA. No Mac, use o Docker, como aqui, ou o OpenSSL do Homebrew.

Para ver se a medição acusa erro, rodamos uma cópia do programa que não alterava a assinatura. Nos três conjuntos a assinatura "alterada" passou e o script apontou o problema.

## Rodar

Só precisa de Python 3.9 ou mais novo.

```
git clone https://github.com/MarcoPeixot/autenticacao_merkle.git
cd autenticacao_merkle
python3 reproduzir.py
```

Leva uns 10 segundos e a saída é esta:

```
ok      testes                     0.1s   OK
ok      teste de mutação           1.4s   8 de 8 defeitos detectados
ok      experimento da posição     2.9s   gravado em docs/experimento-posicao.md
ok      experimento multi-alvo     3.6s   gravado em docs/experimento-multialvo.md
ok      tabela de tamanhos         0.1s   gravado em docs/ e bench/
ok      vetores de teste           0.0s   gravado em vectors/raiz-unica.json

tudo certo em 8.2s
```

Os arquivos em `docs/`, `bench/` e `vectors/` são regravados e têm de sair iguais (`git status` fica limpo).

Não tem dependência externa hoje. O `requirements.txt` está vazio e fica pronto para quando tiver:

```
pip install -r requirements.txt
```

Para rodar uma parte só:

```
python3 -m unittest                             # testes
python3 -m tools.mutacoes                       # teste de mutação dos testes
python3 -m tools.experimento_posicao --gravar   # experimento da posição
python3 -m tools.experimento_multialvo --gravar # experimento multi-alvo
python3 -m tools.tamanhos_de_prova --gravar     # tabela de tamanhos
python3 -m tools.gerar_vetores --gravar         # vetores de teste
```

A comparação com o código do patch, a medição do ML-DSA e os testes do verificador em C ficam fora do `reproduzir.py` porque precisam de Docker. Na primeira vez entra também o download da imagem do Debian.

```
python3 -m tools.comparar_com_patch --gravar   # menos de um minuto
python3 -m tools.medir_ml_dsa --gravar         # uns 10 segundos
python3 -m tools.testar_verificador            # uns 10 segundos
```

Na medição do ML-DSA, tamanhos e checagens saem sempre iguais. Os tempos mudam um pouco a cada execução.

### Verificador em C

`python3 -m tools.testar_verificador` compila o verificador padrão e a
variante com endereços nos hashes internos, no mesmo Debian 13. O teste
compara a raiz única com o Python nos 100 vetores existentes e exercita os
fluxos de múltiplas raízes. Roda duas vezes, a segunda com sanitizadores.

Num Linux com OpenSSL 3.5 ou mais novo, dá para rodar direto com
`make -C verifier test`. A interface está em [`verifier/`](verifier/README.md).
Os formatos e as regras estão em [`spec/`](spec/README.md).

## Falta

- conta do multi-alvo no caso quântico
- revisão da especificação e escolha do conjunto ML-DSA
- modelo Python e vetores compartilhados de múltiplas raízes para o teste diferencial
- medições de tempo e memória
