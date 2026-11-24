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

## Resultados

### Testes

45 de 45 passando, em Python 3.9 e 3.15. No teste de mutação os testes pegaram os 8 defeitos.

### Hipótese da posição: descartada

Tentamos todo módulo com toda posição e com os irmãos de toda prova, em árvores de 1 a 32 módulos. Só deveria passar a posição certa com a prova certa.

| | Patch | Sem posição na folha |
| --- | ---: | ---: |
| Combinações testadas | 680.764 | 680.764 |
| Aceitas indevidamente | 0 | 840 |

No patch nada passa, porque a posição entra no hash da folha. Tirando a posição da folha, o mesmo módulo passa em posições erradas: com 3 módulos, o módulo 2 passa também na posição 3.

O teste só reaproveita provas e módulos legítimos. Buscar colisão é a outra hipótese (multi-alvo), que ainda não testamos.

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

## Rodar

Só precisa de Python 3.9 ou mais novo.

```
git clone https://github.com/MarcoPeixot/autenticacao_merkle.git
cd autenticacao_merkle
python3 reproduzir.py
```

Leva uns 5 segundos e a saída é esta:

```
ok      testes                     0.1s   OK
ok      teste de mutação           1.1s   8 de 8 defeitos detectados
ok      experimento da posição     3.0s   gravado em docs/experimento-posicao.md
ok      tabela de tamanhos         0.1s   gravado em docs/ e bench/
ok      vetores de teste           0.0s   gravado em vectors/raiz-unica.json

tudo certo em 4.4s
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
python3 -m tools.tamanhos_de_prova --gravar     # tabela de tamanhos
python3 -m tools.gerar_vetores --gravar         # vetores de teste
```

## Falta

- comparar com a ferramenta do próprio patch (até agora conferimos lendo o código; rodar precisa de Linux)
- hipótese multi-alvo
- especificação do manifesto e da política
- múltiplas raízes no modelo e nos vetores
- verificador em C
- medições de tempo e memória
