# Verificador em C

O verificador de raiz única reproduz o patch v5. A função
`verificar_raiz_unica`, em `merkle.h`, recebe a raiz confiável, o módulo e a
prova bruta, com seus tamanhos. `mrauth.h` expõe a rota complementar e as
operações de estado. O verificador usa SHA-256 e ML-DSA via EVP do OpenSSL.

## Compilar e testar

É preciso ter compilador C11, Make, `pkg-config` e OpenSSL 3.5 ou mais novo
com `libcrypto`. Os testes usam também Python 3.9 ou mais novo e o comando
`openssl` para assinar dados de teste. A partir da raiz do repositório, rode
o seguinte comando.

```sh
make -C verifier test
```

O comando compara cada decisão de raiz única com o Python e com a resposta
esperada em `vectors/raiz-unica.json`, nas duas compilações. Em seguida roda
os casos de integração de múltiplas raízes, que usam provas calculadas em
Python e assinaturas ML-DSA dos três conjuntos. No Debian 13, rode os mesmos
casos com sanitizadores.

```sh
make -C verifier BUILD_DIR=build/sanitizado \
  CFLAGS='-O1 -g -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' test
```

O `openssl` do macOS é o LibreSSL, sem ML-DSA. No Mac, ou em qualquer máquina
com Docker, `python3 -m tools.testar_verificador` faz as duas rodadas acima
no Debian 13 do repositório, sem gravar nada na pasta.

## Interface de linha de comando

Sem argumentos, `verifier/build/verificar` lê uma linha por caso na entrada padrão, com os
campos `níveis raiz módulo prova` separados por espaços. Os níveis são um
inteiro decimal. Os três outros campos são hexadecimais. Use `-` para
módulo ou prova de comprimento zero. Separe o rodapé do kernel antes de
fornecer a prova.

O programa escreve uma decisão por linha. `OK` indica aceitação, `ENOPKG`
indica tamanho de prova incorreto e `ENOKEY` indica que o caminho não chega à
raiz. `ERRO_CRIPTOGRAFICO` sinaliza falha do OpenSSL. Uma linha malformada
encerra o programa com erro.

## Árvores complementares

Use os arquivos binários descritos na [especificação](../spec/README.md). O
parâmetro `kernel_hex` é o digest confiável da imagem do kernel. Componente e
geração são inteiros decimais. Módulo e prova são arquivos de bytes brutos.

```sh
verifier/build/verificar iniciar politica.bin estado.bin revogacao.bin
verifier/build/verificar complementar politica.bin estado.bin "$kernel_hex" manifesto.bin "$componente" "$geracao" modulo.ko prova.bin
verifier/build/verificar revogar politica.bin estado.bin revogacao-nova.bin
```

`iniciar` valida a tabela assinada e cria o estado. Se o arquivo já existe,
retorna `ESTADO_EXISTENTE`. `revogar` aplica uma tabela assinada mais recente
e preserva as versões aceitas. Use o mesmo caminho em um diretório confiável
para todas as invocações. O programa bloqueia um arquivo `.lock` associado ao
estado e grava a atualização em um temporário no mesmo diretório antes de
substituir o estado por renomeação atômica.

A saída dessas operações é `motivo raiz autoridade`. `OK` indica aceitação.
Raiz e autoridade saem como `- -` até o manifesto passar por R2. Decisões de
recusa também são escritas na saída padrão e retornam status de processo 1.

Chamadores da API C recebem uma atualização no `estado_novo` sempre que
há uma mudança a persistir. Devem manter a exclusão mútua desde a leitura
do estado, persistir a atualização antes de usar a aceitação e liberar
`estado_novo.dados` com `free`.

O alvo `make -C verifier enderecos` gera `verifier/build/verificar-enderecos`
com os endereços em cada hash interno complementar. Use manifestos de
formato `2` e um estado separado para medir essa variante.
