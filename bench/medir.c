/*
 * Mede o verificador em C (verifier/) numa configuração dos conjuntos de teste.
 *
 * Uso: medir <pasta da configuração> <44|65|87> <rodadas>
 *
 * A pasta é uma das que `python3 -m tools.conjuntos --arquivos` grava
 * (<variante>/<N>x<R>/). Compilado com -DMERKLE_ENDERECOS, mede a variante com
 * endereços, que lê manifestos de formato 2.
 *
 * Antes de medir, cada caso passa uma vez por cada operação e tem de ser
 * aceito. Se algum não for, o programa para sem medir nada. Antes das rodadas
 * de cada operação há mais uma passada, de aquecimento, fora da conta.
 *
 * Operações (cada rodada cronometra o lote inteiro, repetido até durar ao menos
 * 1 ms, e divide pelo número de itens verificados):
 *   principal             verificar_raiz_unica, por módulo da árvore principal
 *   caminho_complementar  verificar_prova_complementar, por módulo complementar
 *   manifesto             conferência ML-DSA do manifesto, por árvore complementar
 *   complementar          verificar_complementar inteiro (R2 a R8), por módulo complementar
 *
 * Saída, uma linha por item, lida por tools/benchmark.py:
 *   casos <operação> <itens> <repetições do lote por rodada>
 *   tempo <operação> <µs por item em cada rodada...>
 *   memoria <pico em bytes> <bytes das entradas> <bytes do estado>
 */
#define _POSIX_C_SOURCE 200809L
/* ru_maxrss não é POSIX: o glibc e o macOS só mostram com estas. */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include <openssl/evp.h>

#include "arquivos.h"
#include "formatos.h"
#include "mrauth.h"

#define MAX_RODADAS 1000
#define MAX_ARVORES 64
/* Lotes pequenos (8 módulos levam uns 8 µs) se repetem até a rodada durar ao menos isto. */
#define RODADA_MINIMA_US 1000.0

enum { PRINCIPAL, CAMINHO, MANIFESTO, COMPLEMENTAR, OPERACOES };
static const char *const operacoes[OPERACOES] = {
    "principal", "caminho_complementar", "manifesto", "complementar",
};

struct caso {
    uint32_t arvore;
    uint32_t componente;
    uint64_t geracao;
    struct bytes modulo;
    struct bytes prova;
};

struct arvore {
    uint32_t id;
    struct buffer bruto;
    struct manifesto manifesto;
    struct politica_mrauth politica;
};

static struct caso *casos;
static size_t total_casos;
static size_t *principais, *complementares;
static size_t total_principais, total_complementares;
static struct arvore arvores[MAX_ARVORES];
static size_t total_arvores;

static struct raiz_merkle raiz_principal;
static struct buffer kernel, politica, revogacao, estado;
static size_t bytes_entradas;
static double tempos[OPERACOES][MAX_RODADAS];
static int repeticoes[OPERACOES];

static void falhou(const char *formato, const char *detalhe)
{
    fprintf(stderr, "medir: ");
    fprintf(stderr, formato, detalhe);
    fprintf(stderr, "\n");
    exit(1);
}

static struct bytes bytes_de(const struct buffer *buffer)
{
    return (struct bytes){ buffer->dados, buffer->tamanho };
}

static struct buffer ler(const char *pasta, const char *nome)
{
    char caminho[4096];
    struct buffer saida = {0};
    if ((size_t)snprintf(caminho, sizeof(caminho), "%s/%s", pasta, nome) >= sizeof(caminho) ||
        !ler_arquivo(caminho, &saida))
        falhou("não consegui ler %s", caminho);
    bytes_entradas += saida.tamanho;
    return saida;
}

static const unsigned char *pedaco(const struct buffer *dados, size_t *posicao, size_t tamanho)
{
    if (tamanho > dados->tamanho - *posicao)
        falhou("%s", "casos.bin cortado");
    const unsigned char *inicio = dados->dados + *posicao;
    *posicao += tamanho;
    return inicio;
}

static struct arvore *arvore_de(uint32_t id)
{
    for (size_t i = 0; i < total_arvores; i++) {
        if (arvores[i].id == id)
            return &arvores[i];
    }
    return NULL;
}

static void carregar(const char *pasta, int conjunto)
{
    struct buffer raiz = ler(pasta, "raiz.bin");
    if (raiz.tamanho != 4 + HASH_BYTES)
        falhou("%s", "raiz.bin deveria ter 36 bytes");
    raiz_principal.niveis = ler_u32(raiz.dados);
    memcpy(raiz_principal.hash, raiz.dados + 4, HASH_BYTES);
    free(raiz.dados);

    kernel = ler(pasta, "kernel.bin");
    if (kernel.tamanho != HASH_BYTES)
        falhou("%s", "kernel.bin deveria ter 32 bytes");

    /* casos.bin: árvore:u32 componente:u32 geração:u64 tamanho:u32 módulo tamanho:u32 prova */
    static struct buffer dados;
    dados = ler(pasta, "casos.bin");
    size_t capacidade = 1024, posicao = 0;
    casos = malloc(capacidade * sizeof(*casos));
    while (casos && posicao < dados.tamanho) {
        if (total_casos == capacidade)
            casos = realloc(casos, (capacidade *= 2) * sizeof(*casos));
        if (casos == NULL)
            break;
        struct caso *c = &casos[total_casos++];
        const unsigned char *cabecalho = pedaco(&dados, &posicao, 20);
        c->arvore = ler_u32(cabecalho);
        c->componente = ler_u32(cabecalho + 4);
        c->geracao = ler_u64(cabecalho + 8);
        c->modulo.tamanho = ler_u32(cabecalho + 16);
        c->modulo.dados = pedaco(&dados, &posicao, c->modulo.tamanho);
        c->prova.tamanho = ler_u32(pedaco(&dados, &posicao, 4));
        c->prova.dados = pedaco(&dados, &posicao, c->prova.tamanho);
    }
    principais = malloc((total_casos + 1) * sizeof(size_t));
    complementares = malloc((total_casos + 1) * sizeof(size_t));
    if (casos == NULL || principais == NULL || complementares == NULL)
        falhou("%s", "sem memória");

    char subpasta[4096];
    snprintf(subpasta, sizeof(subpasta), "%s/ml-dsa-%d", pasta, conjunto);
    for (size_t i = 0; i < total_casos; i++) {
        if (casos[i].arvore == 0) {
            principais[total_principais++] = i;
            continue;
        }
        complementares[total_complementares++] = i;
        if (arvore_de(casos[i].arvore) != NULL)
            continue;
        if (total_arvores == MAX_ARVORES)
            falhou("%s", "árvores demais");
        char nome[64];
        snprintf(nome, sizeof(nome), "manifesto-%" PRIu32 ".bin", casos[i].arvore);
        struct arvore *a = &arvores[total_arvores++];
        a->id = casos[i].arvore;
        a->bruto = ler(subpasta, nome);
        if (!ler_manifesto(bytes_de(&a->bruto), &a->manifesto))
            falhou("manifesto %s inválido para esta compilação", nome);
    }

    if (total_arvores == 0)
        return;
    politica = ler(subpasta, "politica.bin");
    revogacao = ler(subpasta, "revogacao.bin");
    for (size_t i = 0; i < total_arvores; i++) {
        struct arvore *a = &arvores[i];
        uint32_t componente = 0;
        for (size_t j = 0; j < total_complementares; j++) {
            if (casos[complementares[j]].arvore == a->id) {
                componente = casos[complementares[j]].componente;
                break;
            }
        }
        if (!ler_politica(bytes_de(&politica), &a->manifesto, componente, &a->politica) ||
            a->politica.chave_autoridade == NULL)
            falhou("%s", "a política não tem a autoridade de um manifesto");
    }
}

/* --- As operações. Cada uma recebe o índice do item no seu lote. --- */

static enum resultado_merkle op_principal(size_t i)
{
    const struct caso *c = &casos[principais[i]];
    return verificar_raiz_unica(&raiz_principal, c->modulo.dados, c->modulo.tamanho,
                                c->prova.dados, c->prova.tamanho);
}

static enum resultado_merkle op_caminho(size_t i)
{
    const struct caso *c = &casos[complementares[i]];
    const struct arvore *a = arvore_de(c->arvore);
    const struct folha_complementar folha = {
        a->id, a->manifesto.numero_folhas, c->componente, c->geracao,
    };
    return verificar_prova_complementar(&a->manifesto.raiz, &folha, c->modulo, c->prova);
}

/* O mesmo que verificar_assinatura, em verifier/mrauth.c, que é estática. */
static enum resultado_merkle op_manifesto(size_t i)
{
    const struct arvore *a = &arvores[i];
    const struct conjunto_ml_dsa *conjunto = a->politica.conjunto;
    EVP_PKEY *chave = EVP_PKEY_new_raw_public_key_ex(NULL, conjunto->nome, NULL,
                                                    a->politica.chave_autoridade, conjunto->chave_bytes);
    EVP_PKEY_CTX *ctx = chave ? EVP_PKEY_CTX_new_from_pkey(NULL, chave, NULL) : NULL;
    EVP_SIGNATURE *algoritmo = EVP_SIGNATURE_fetch(NULL, conjunto->nome, NULL);
    int verificou = -1;
    if (ctx && algoritmo && EVP_PKEY_verify_message_init(ctx, algoritmo, NULL) == 1 &&
        a->bruto.tamanho > conjunto->assinatura_bytes) {
        size_t mensagem = a->bruto.tamanho - conjunto->assinatura_bytes;
        verificou = EVP_PKEY_verify(ctx, a->bruto.dados + mensagem, conjunto->assinatura_bytes,
                                    a->bruto.dados, mensagem);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(algoritmo);
    EVP_PKEY_free(chave);
    if (verificou == 1)
        return MERKLE_OK;
    return verificou == 0 ? MERKLE_ASSINATURA_INVALIDA : MERKLE_ERRO_CRIPTOGRAFICO;
}

static struct decisao_mrauth complementar(size_t i, struct buffer *novo)
{
    const struct caso *c = &casos[complementares[i]];
    const struct arvore *a = arvore_de(c->arvore);
    const struct entrada_mrauth entrada = {
        .kernel = kernel.dados, .manifesto = bytes_de(&a->bruto),
        .modulo = c->modulo, .prova = c->prova,
        .componente = c->componente, .geracao = c->geracao,
    };
    return verificar_complementar(bytes_de(&politica), bytes_de(&estado), &entrada, novo);
}

static enum resultado_merkle op_complementar(size_t i)
{
    struct buffer novo;
    struct decisao_mrauth decisao = complementar(i, &novo);
    if (novo.dados != NULL) {
        /* Com o estado já aceito, nenhuma verificação deveria pedir gravação. */
        free(novo.dados);
        return MERKLE_ERRO_PERSISTENCIA;
    }
    return decisao.motivo;
}

typedef enum resultado_merkle (*operacao)(size_t);

static double agora_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static size_t itens(int op)
{
    switch (op) {
    case PRINCIPAL: return total_principais;
    case CAMINHO: case COMPLEMENTAR: return total_complementares;
    default: return total_arvores;
    }
}

static operacao funcao(int op)
{
    static const operacao funcoes[OPERACOES] = { op_principal, op_caminho, op_manifesto, op_complementar };
    return funcoes[op];
}

/* Passa todos os itens uma vez e para se algum não for aceito. Serve também de aquecimento. */
static void conferir(int op)
{
    for (size_t i = 0; i < itens(op); i++) {
        enum resultado_merkle motivo = funcao(op)(i);
        if (motivo != MERKLE_OK) {
            fprintf(stderr, "medir: %s recusou o item %zu (motivo %d); nada foi medido\n",
                    operacoes[op], i, (int)motivo);
            exit(1);
        }
    }
}

/* Deixa a versão de cada árvore aceita, para as rodadas não pedirem gravação de estado. */
static void provisionar(void)
{
    if (iniciar_estado(bytes_de(&politica), bytes_de(&revogacao), &estado) != MERKLE_OK)
        falhou("%s", "a tabela de revogação não foi aceita");
    for (size_t t = 0; t < total_arvores; t++) {
        for (size_t i = 0; i < total_complementares; i++) {
            if (casos[complementares[i]].arvore != arvores[t].id)
                continue;
            struct buffer novo;
            if (complementar(i, &novo).motivo != MERKLE_OK || novo.dados == NULL)
                falhou("%s", "a primeira verificação de uma árvore não foi aceita");
            free(estado.dados);
            estado = novo;
            break;
        }
    }
}

/*
 * Pico de memória residente deste processo, em bytes. No Linux vem do VmHWM de
 * /proc/self/status: o ru_maxrss sobrevive ao exec e traria o pico do processo
 * que chamou o medidor (o Python do benchmark). No macOS o ru_maxrss já é só
 * deste processo, em bytes.
 */
static size_t pico_de_memoria(void)
{
#ifdef __linux__
    FILE *status = fopen("/proc/self/status", "r");
    if (status != NULL) {
        char linha[256];
        size_t kb = 0;
        while (fgets(linha, sizeof(linha), status) != NULL) {
            if (sscanf(linha, "VmHWM: %zu kB", &kb) == 1)
                break;
        }
        fclose(status);
        if (kb > 0)
            return kb * 1024;
    }
#endif
    struct rusage uso;
    getrusage(RUSAGE_SELF, &uso);
#ifdef __APPLE__
    return (size_t)uso.ru_maxrss;
#else
    return (size_t)uso.ru_maxrss * 1024;
#endif
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <pasta da configuração> <44|65|87> <rodadas>\n", argv[0]);
        return 1;
    }
    int conjunto = atoi(argv[2]);
    int rodadas = atoi(argv[3]);
    if ((conjunto != 44 && conjunto != 65 && conjunto != 87) || rodadas < 1 || rodadas > MAX_RODADAS) {
        fprintf(stderr, "medir: conjunto 44, 65 ou 87 e de 1 a %d rodadas\n", MAX_RODADAS);
        return 1;
    }

    carregar(argv[1], conjunto);
    if (total_arvores > 0)
        provisionar();

    for (int op = 0; op < OPERACOES; op++) {
        if (itens(op) > 0)
            conferir(op);
    }
    for (int op = 0; op < OPERACOES; op++) {
        const size_t n = itens(op);
        if (n == 0)
            continue;
        const operacao f = funcao(op);

        /* Aquecimento logo antes das rodadas, que também diz quanto dura o lote. */
        double inicio = agora_us();
        conferir(op);
        double lote_us = agora_us() - inicio;
        repeticoes[op] = lote_us >= RODADA_MINIMA_US ? 1 : (int)(RODADA_MINIMA_US / (lote_us > 0 ? lote_us : 1)) + 1;

        for (int r = 0; r < rodadas; r++) {
            int recusas = 0;
            inicio = agora_us();
            for (int k = 0; k < repeticoes[op]; k++) {
                for (size_t i = 0; i < n; i++)
                    recusas += f(i) != MERKLE_OK;
            }
            tempos[op][r] = (agora_us() - inicio) / ((double)n * repeticoes[op]);
            if (recusas) {
                fprintf(stderr, "medir: %s recusou %d itens numa rodada\n", operacoes[op], recusas);
                return 1;
            }
        }
    }

    for (int op = 0; op < OPERACOES; op++) {
        if (itens(op) == 0)
            continue;
        printf("casos %s %zu %d\n", operacoes[op], itens(op), repeticoes[op]);
        printf("tempo %s", operacoes[op]);
        for (int r = 0; r < rodadas; r++)
            printf(" %.4f", tempos[op][r]);
        printf("\n");
    }
    printf("memoria %zu %zu %zu\n", pico_de_memoria(), bytes_entradas, estado.tamanho);
    return fflush(stdout) == 0 ? 0 : 1;
}
