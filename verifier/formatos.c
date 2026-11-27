#include "formatos.h"

#include <stdlib.h>
#include <string.h>

enum { AUTORIZACAO_BYTES = 16, REVOGACAO_CABECALHO = 17, ESTADO_CABECALHO = 9 };

static const struct conjunto_ml_dsa conjuntos[] = {
    { 44, "ML-DSA-44", 1312, 2420 },
    { 65, "ML-DSA-65", 1952, 3309 },
    { 87, "ML-DSA-87", 2592, 4627 },
};

static const unsigned char *consumir(struct bytes *resto, size_t tamanho)
{
    if (tamanho > resto->tamanho)
        return NULL;

    const unsigned char *inicio = resto->dados;
    resto->dados += tamanho;
    resto->tamanho -= tamanho;
    return inicio;
}

static bool cabecalho(struct bytes bruto, const char marcador[4], unsigned char versao)
{
    return bruto.tamanho >= 5 && memcmp(bruto.dados, marcador, 4) == 0 && bruto.dados[4] == versao;
}

bool ler_manifesto(struct bytes bruto, struct manifesto *saida)
{
#ifdef MERKLE_ENDERECOS
    const unsigned char formato = 2;
#else
    const unsigned char formato = 1;
#endif
    if (bruto.tamanho < MANIFESTO_BYTES || !cabecalho(bruto, "AMMF", formato))
        return false;

    const unsigned char *dados = bruto.dados;
    saida->arvore = ler_u32(dados + 5);
    saida->autoridade = ler_u32(dados + 9);
    saida->versao = ler_u64(dados + 13);
    saida->kernel = dados + 21;
    saida->numero_folhas = ler_u32(dados + 53);
    saida->raiz.niveis = dados[57];
    memcpy(saida->raiz.hash, dados + 58, HASH_BYTES);
    saida->permissoes = ler_u64(dados + 90);
    return saida->arvore != 0 && saida->autoridade != 0 && saida->versao != 0;
}

static bool ler_autorizacoes(struct bytes *resto, uint32_t quantidade, uint32_t autoridade,
                             const struct manifesto *manifesto, uint32_t componente,
                             struct politica_mrauth *saida)
{
    if (quantidade > resto->tamanho / AUTORIZACAO_BYTES)
        return false;

    uint32_t arvore_anterior = 0, componente_anterior = 0;
    for (uint32_t i = 0; i < quantidade; i++) {
        const unsigned char *entrada = consumir(resto, AUTORIZACAO_BYTES);
        uint32_t arvore = ler_u32(entrada);
        uint32_t atual = ler_u32(entrada + 4);
        if (arvore == 0 || arvore < arvore_anterior ||
            (arvore == arvore_anterior && atual <= componente_anterior))
            return false;
        arvore_anterior = arvore;
        componente_anterior = atual;

        if (manifesto && arvore == manifesto->arvore) {
            if (autoridade == manifesto->autoridade) {
                saida->autoriza_arvore = true;
                if (atual == componente)
                    saida->autorizacao = entrada;
            } else {
                saida->arvore_ambigua = true;
            }
        }
    }
    return true;
}

bool ler_politica(struct bytes bruto, const struct manifesto *manifesto, uint32_t componente,
                  struct politica_mrauth *saida)
{
    if (bruto.tamanho < 6 || !cabecalho(bruto, "AMPO", 1))
        return false;

    *saida = (struct politica_mrauth){0};
    for (size_t i = 0; i < sizeof(conjuntos) / sizeof(conjuntos[0]); i++) {
        if (bruto.dados[5] == conjuntos[i].id)
            saida->conjunto = &conjuntos[i];
    }
    if (saida->conjunto == NULL)
        return false;

    const size_t chave_bytes = saida->conjunto->chave_bytes;
    consumir(&bruto, 6);
    saida->chave_revogacao = consumir(&bruto, chave_bytes);
    const unsigned char *quantidade = consumir(&bruto, 4);
    if (saida->chave_revogacao == NULL || quantidade == NULL)
        return false;

    uint32_t anterior = 0;
    uint32_t total = ler_u32(quantidade);
    for (uint32_t i = 0; i < total; i++) {
        const unsigned char *entrada = consumir(&bruto, chave_bytes + 8);
        if (entrada == NULL)
            return false;

        uint32_t autoridade = ler_u32(entrada);
        if (autoridade <= anterior)
            return false;
        anterior = autoridade;
        if (manifesto && autoridade == manifesto->autoridade)
            saida->chave_autoridade = entrada + 4;
        if (!ler_autorizacoes(&bruto, ler_u32(entrada + 4 + chave_bytes), autoridade,
                              manifesto, componente, saida))
            return false;
    }
    return bruto.tamanho == 0;
}

static bool ler_registros(struct bytes bruto, uint32_t quantidade, bool versoes,
                          struct registros *saida)
{
    if (bruto.tamanho % REGISTRO_BYTES != 0 || bruto.tamanho / REGISTRO_BYTES != quantidade)
        return false;

    uint32_t anterior = 0;
    const unsigned char *entrada = bruto.dados;
    for (uint32_t i = 0; i < quantidade; i++, entrada += REGISTRO_BYTES) {
        uint32_t id = ler_u32(entrada);
        if ((i != 0 && id <= anterior) || (versoes && (id == 0 || ler_u64(entrada + 4) == 0)))
            return false;
        anterior = id;
    }
    *saida = (struct registros){ bruto.dados, quantidade };
    return true;
}

bool ler_revogacao(struct bytes bruto, size_t assinatura_bytes, struct tabela_revogacao *saida)
{
    if (bruto.tamanho < REVOGACAO_CABECALHO + assinatura_bytes || bruto.tamanho > UINT32_MAX ||
        !cabecalho(bruto, "AMRV", 1))
        return false;

    saida->bruta = bruto;
    saida->versao = ler_u64(bruto.dados + 5);
    struct bytes entradas = {
        bruto.dados + REVOGACAO_CABECALHO, bruto.tamanho - REVOGACAO_CABECALHO - assinatura_bytes,
    };
    return saida->versao != 0 && ler_registros(entradas, ler_u32(bruto.dados + 13), false,
                                              &saida->geracoes);
}

bool ler_estado(struct bytes bruto, size_t assinatura_bytes, struct estado_mrauth *saida)
{
    if (bruto.tamanho < ESTADO_CABECALHO || !cabecalho(bruto, "AMES", 1))
        return false;

    size_t tamanho = ler_u32(bruto.dados + 5);
    consumir(&bruto, ESTADO_CABECALHO);
    const unsigned char *tabela = consumir(&bruto, tamanho);
    const unsigned char *quantidade = consumir(&bruto, 4);
    return tabela && quantidade && ler_revogacao((struct bytes){ tabela, tamanho }, assinatura_bytes,
                                                 &saida->revogacao) &&
           ler_registros(bruto, ler_u32(quantidade), true, &saida->versoes);
}

static size_t buscar(const struct registros *lista, uint32_t id)
{
    size_t inicio = 0, fim = lista->quantidade;
    while (inicio < fim) {
        size_t meio = inicio + (fim - inicio) / 2;
        if (ler_u32(lista->dados + meio * REGISTRO_BYTES) < id)
            inicio = meio + 1;
        else
            fim = meio;
    }
    return inicio;
}

static bool contem(const struct registros *lista, size_t posicao, uint32_t id)
{
    return posicao < lista->quantidade && ler_u32(lista->dados + posicao * REGISTRO_BYTES) == id;
}

uint64_t valor_registro(const struct registros *lista, uint32_t id)
{
    size_t posicao = buscar(lista, id);
    return contem(lista, posicao, id) ? ler_u64(lista->dados + posicao * REGISTRO_BYTES + 4) : 0;
}

bool montar_estado(struct bytes tabela, const struct registros *versoes,
                   uint32_t arvore, uint64_t versao, struct buffer *saida)
{
    const size_t fixo = ESTADO_CABECALHO + 4;
    size_t posicao = arvore ? buscar(versoes, arvore) : versoes->quantidade;
    bool substitui = arvore && contem(versoes, posicao, arvore);
    size_t acrescenta = arvore && !substitui;
    if (versoes->quantidade > UINT32_MAX - acrescenta || tabela.tamanho > UINT32_MAX ||
        tabela.tamanho > SIZE_MAX - fixo)
        return false;

    size_t quantidade = versoes->quantidade + acrescenta;
    if (quantidade > (SIZE_MAX - fixo - tabela.tamanho) / REGISTRO_BYTES)
        return false;

    size_t tamanho = fixo + tabela.tamanho + quantidade * REGISTRO_BYTES;
    unsigned char *dados = malloc(tamanho);
    if (dados == NULL)
        return false;

    memcpy(dados, "AMES\x01", 5);
    gravar_u32(dados + 5, (uint32_t)tabela.tamanho);
    memcpy(dados + ESTADO_CABECALHO, tabela.dados, tabela.tamanho);
    gravar_u32(dados + ESTADO_CABECALHO + tabela.tamanho, (uint32_t)quantidade);
    unsigned char *destino = dados + fixo + tabela.tamanho;
    if (posicao != 0)
        memcpy(destino, versoes->dados, posicao * REGISTRO_BYTES);
    if (arvore) {
        unsigned char *entrada = destino + posicao * REGISTRO_BYTES;
        gravar_u32(entrada, arvore);
        gravar_u64(entrada + 4, versao);
        size_t inicio = posicao + substitui;
        if (inicio < versoes->quantidade)
            memcpy(entrada + REGISTRO_BYTES, versoes->dados + inicio * REGISTRO_BYTES,
                   (versoes->quantidade - inicio) * REGISTRO_BYTES);
    }
    *saida = (struct buffer){ dados, tamanho };
    return true;
}
