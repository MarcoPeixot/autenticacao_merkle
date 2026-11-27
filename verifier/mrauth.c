#include "mrauth.h"

#include <string.h>

#include <openssl/evp.h>

#include "formatos.h"

static enum resultado_merkle verificar_assinatura(const struct conjunto_ml_dsa *conjunto,
                                                  const unsigned char *publica, struct bytes objeto)
{
    EVP_PKEY *chave = EVP_PKEY_new_raw_public_key_ex(NULL, conjunto->nome, NULL,
                                                    publica, conjunto->chave_bytes);
    EVP_PKEY_CTX *ctx = chave ? EVP_PKEY_CTX_new_from_pkey(NULL, chave, NULL) : NULL;
    EVP_SIGNATURE *algoritmo = EVP_SIGNATURE_fetch(NULL, conjunto->nome, NULL);
    int verificou = -1;
    if (ctx && algoritmo && EVP_PKEY_verify_message_init(ctx, algoritmo, NULL) == 1) {
        size_t mensagem = objeto.tamanho - conjunto->assinatura_bytes;
        verificou = EVP_PKEY_verify(ctx, objeto.dados + mensagem, conjunto->assinatura_bytes,
                                    objeto.dados, mensagem);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(algoritmo);
    EVP_PKEY_free(chave);

    if (verificou == 1)
        return MERKLE_OK;
    return verificou == 0 ? MERKLE_ASSINATURA_INVALIDA : MERKLE_ERRO_CRIPTOGRAFICO;
}

static enum resultado_merkle autenticar_manifesto(const struct politica_mrauth *politica,
                                                  const struct manifesto *manifesto,
                                                  const struct entrada_mrauth *entrada)
{
    if (politica->chave_autoridade == NULL)
        return MERKLE_AUTORIDADE_NAO_AUTORIZADA;

    enum resultado_merkle motivo = verificar_assinatura(politica->conjunto, politica->chave_autoridade,
                                                        entrada->manifesto);
    if (motivo != MERKLE_OK)
        return motivo;
    if (!politica->autoriza_arvore || politica->arvore_ambigua)
        return MERKLE_AUTORIDADE_NAO_AUTORIZADA;
    if (memcmp(entrada->kernel, manifesto->kernel, HASH_BYTES) != 0)
        return MERKLE_KERNEL_INCOMPATIVEL;
    return MERKLE_OK;
}

static bool resumir_manifesto(struct bytes manifesto, unsigned char resumo[HASH_BYTES])
{
    return EVP_Digest(manifesto.dados, MANIFESTO_BYTES, resumo, NULL, EVP_sha256(), NULL) == 1;
}

static uint32_t profundidade(uint32_t folhas)
{
    if (folhas <= 1)
        return 1;

    uint32_t niveis = 0;
    for (uint32_t valor = folhas - 1; valor != 0; valor >>= 1)
        niveis++;
    return niveis;
}

static enum resultado_merkle conferir_modulo(const struct politica_mrauth *politica,
                                             const struct estado_mrauth *estado,
                                             const struct manifesto *manifesto,
                                             const struct entrada_mrauth *entrada,
                                             struct buffer *estado_novo)
{
    const unsigned char *aceito = buscar_registro(&estado->versoes, manifesto->arvore);
    const uint64_t versao_anterior = aceito ? ler_u64(aceito + 4) : 0;
    unsigned char resumo[HASH_BYTES];
    if (!resumir_manifesto(entrada->manifesto, resumo))
        return MERKLE_ERRO_CRIPTOGRAFICO;
    if (manifesto->versao < versao_anterior)
        return MERKLE_ROLLBACK;
    if (aceito && manifesto->versao == versao_anterior &&
        memcmp(resumo, aceito + VERSAO_RESUMO, HASH_BYTES) != 0)
        return MERKLE_ROLLBACK;
    if (manifesto->numero_folhas == 0 || manifesto->raiz.niveis != profundidade(manifesto->numero_folhas))
        return MERKLE_FORMATO_INVALIDO;

    const struct folha_complementar folha = {
        manifesto->arvore, manifesto->numero_folhas, entrada->componente, entrada->geracao,
    };
    enum resultado_merkle motivo = verificar_prova_complementar(&manifesto->raiz, &folha,
                                                                entrada->modulo, entrada->prova);
    if (motivo != MERKLE_OK)
        return motivo;
    if (entrada->geracao < valor_registro(&estado->revogacao.geracoes, entrada->componente))
        return MERKLE_REVOGADO;
    if (politica->autorizacao == NULL)
        return MERKLE_COMPONENTE_NAO_AUTORIZADO;
    if ((manifesto->permissoes & ~ler_u64(politica->autorizacao + 8)) != 0)
        return MERKLE_PERMISSAO_NEGADA;
    if (manifesto->versao > versao_anterior &&
        !montar_estado(estado->revogacao.bruta, &estado->versoes, manifesto->arvore,
                       manifesto->versao, resumo, estado_novo))
        return MERKLE_ERRO_PERSISTENCIA;
    return MERKLE_OK;
}

struct decisao_mrauth verificar_complementar(
    struct bytes politica_bruta, struct bytes estado_bruto, const struct entrada_mrauth *entrada,
    struct buffer *estado_novo)
{
    *estado_novo = (struct buffer){0};
    struct decisao_mrauth decisao = { .motivo = MERKLE_FORMATO_INVALIDO };
    struct manifesto manifesto;
    struct politica_mrauth politica;
    struct estado_mrauth estado;
    if (!ler_manifesto(entrada->manifesto, &manifesto) ||
        !ler_politica(politica_bruta, &manifesto, entrada->componente, &politica) ||
        entrada->manifesto.tamanho != MANIFESTO_BYTES + politica.conjunto->assinatura_bytes ||
        !ler_estado(estado_bruto, politica.conjunto->assinatura_bytes, &estado))
        return decisao;

    decisao.motivo = autenticar_manifesto(&politica, &manifesto, entrada);
    if (decisao.motivo != MERKLE_OK)
        return decisao;

    decisao.autoridade = manifesto.autoridade;
    decisao.raiz = manifesto.raiz;
    decisao.motivo = conferir_modulo(&politica, &estado, &manifesto, entrada, estado_novo);
    return decisao;
}

enum resultado_merkle iniciar_estado(
    struct bytes politica_bruta, struct bytes tabela, struct buffer *estado_novo)
{
    *estado_novo = (struct buffer){0};
    struct politica_mrauth politica;
    struct tabela_revogacao revogacao;
    if (!ler_politica(politica_bruta, NULL, 0, &politica) ||
        !ler_revogacao(tabela, politica.conjunto->assinatura_bytes, &revogacao))
        return MERKLE_FORMATO_INVALIDO;

    enum resultado_merkle motivo = verificar_assinatura(politica.conjunto, politica.chave_revogacao, tabela);
    if (motivo != MERKLE_OK)
        return motivo;
    const struct registros vazio = { .largura = VERSAO_BYTES };
    return montar_estado(tabela, &vazio, 0, 0, NULL, estado_novo) ? MERKLE_OK : MERKLE_ERRO_PERSISTENCIA;
}

enum resultado_merkle atualizar_revogacao(
    struct bytes politica_bruta, struct bytes estado_bruto, struct bytes tabela,
    struct buffer *estado_novo)
{
    *estado_novo = (struct buffer){0};
    struct politica_mrauth politica;
    struct estado_mrauth estado;
    struct tabela_revogacao nova;
    if (!ler_politica(politica_bruta, NULL, 0, &politica) ||
        !ler_estado(estado_bruto, politica.conjunto->assinatura_bytes, &estado) ||
        !ler_revogacao(tabela, politica.conjunto->assinatura_bytes, &nova))
        return MERKLE_FORMATO_INVALIDO;

    enum resultado_merkle motivo = verificar_assinatura(politica.conjunto, politica.chave_revogacao, tabela);
    if (motivo != MERKLE_OK)
        return motivo;

    const struct tabela_revogacao *anterior = &estado.revogacao;
    if (nova.versao < anterior->versao)
        return MERKLE_ROLLBACK;
    if (nova.versao == anterior->versao) {
        if (tabela.tamanho == anterior->bruta.tamanho &&
            memcmp(tabela.dados, anterior->bruta.dados,
                   tabela.tamanho - politica.conjunto->assinatura_bytes) == 0)
            return MERKLE_OK;
        return MERKLE_ROLLBACK;
    }

    const unsigned char *registro = anterior->geracoes.dados;
    for (uint32_t i = 0; i < anterior->geracoes.quantidade; i++, registro += GERACAO_BYTES) {
        if (valor_registro(&nova.geracoes, ler_u32(registro)) < ler_u64(registro + 4))
            return MERKLE_REVOGACAO_REGRESSIVA;
    }
    return montar_estado(tabela, &estado.versoes, 0, 0, NULL, estado_novo) ? MERKLE_OK : MERKLE_ERRO_PERSISTENCIA;
}
