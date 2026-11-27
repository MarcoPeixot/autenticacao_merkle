#include "merkle.h"

#include <string.h>

#include <openssl/evp.h>

enum { POSICAO_BYTES = 4 };

static enum resultado_merkle verificar_prova(
    const struct raiz_merkle *raiz, const struct folha_complementar *complementar,
    struct bytes modulo, struct bytes prova)
{
    if (prova.tamanho < POSICAO_BYTES)
        return MERKLE_ENOPKG;

    const size_t tamanho_irmaos = prova.tamanho - POSICAO_BYTES;
    if (tamanho_irmaos % HASH_BYTES != 0 || tamanho_irmaos / HASH_BYTES != raiz->niveis)
        return MERKLE_ENOPKG;

    uint32_t posicao = ler_u32(prova.dados);
    if (complementar && posicao >= complementar->numero_folhas)
        return MERKLE_POSICAO_INVALIDA;

    unsigned char folha[21];
    size_t tamanho_folha;
    if (complementar) {
        folha[0] = 0x03;
        gravar_u32(folha + 1, complementar->arvore);
        gravar_u32(folha + 5, posicao);
        gravar_u32(folha + 9, complementar->componente);
        gravar_u64(folha + 13, complementar->geracao);
        tamanho_folha = sizeof(folha);
    } else {
        folha[0] = 0x01;
        memcpy(folha + 1, prova.dados, POSICAO_BYTES);
        tamanho_folha = 1 + POSICAO_BYTES;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return MERKLE_ERRO_CRIPTOGRAFICO;

    enum resultado_merkle resultado = MERKLE_ERRO_CRIPTOGRAFICO;
    const EVP_MD *sha256 = EVP_sha256();
    unsigned char atual[HASH_BYTES];
    if (EVP_DigestInit_ex(ctx, sha256, NULL) != 1 ||
        EVP_DigestUpdate(ctx, folha, tamanho_folha) != 1 ||
        EVP_DigestUpdate(ctx, modulo.dados, modulo.tamanho) != 1 ||
        EVP_DigestFinal_ex(ctx, atual, NULL) != 1)
        goto fim;

#ifdef MERKLE_ENDERECOS
    unsigned char no[10 + 2 * HASH_BYTES] = { 0x02 };
    size_t prefixo_no = complementar ? 10 : 1;
    if (complementar) {
        no[0] = 0x04;
        gravar_u32(no + 1, complementar->arvore);
    }
#else
    unsigned char no[1 + 2 * HASH_BYTES] = { 0x02 };
    const size_t prefixo_no = 1;
#endif
    const unsigned char *irmao = prova.dados + POSICAO_BYTES;
    for (uint32_t nivel = 0; nivel < raiz->niveis; nivel++) {
#ifdef MERKLE_ENDERECOS
        if (complementar) {
            no[5] = (unsigned char)nivel;
            gravar_u32(no + 6, posicao >> 1);
        }
#endif
        const size_t lado = (posicao & 1u) * HASH_BYTES;
        memcpy(no + prefixo_no + lado, atual, HASH_BYTES);
        memcpy(no + prefixo_no + (HASH_BYTES - lado), irmao, HASH_BYTES);
        if (EVP_DigestInit_ex(ctx, sha256, NULL) != 1 ||
            EVP_DigestUpdate(ctx, no, prefixo_no + 2 * HASH_BYTES) != 1 ||
            EVP_DigestFinal_ex(ctx, atual, NULL) != 1)
            goto fim;

        irmao += HASH_BYTES;
        posicao >>= 1;
    }

    resultado = memcmp(atual, raiz->hash, HASH_BYTES) == 0 ? MERKLE_OK : MERKLE_ENOKEY;

fim:
    EVP_MD_CTX_free(ctx);
    return resultado;
}

enum resultado_merkle verificar_raiz_unica(
    const struct raiz_merkle *raiz,
    const unsigned char *modulo, size_t tamanho_modulo,
    const unsigned char *prova, size_t tamanho_prova)
{
    return verificar_prova(raiz, NULL, (struct bytes){ modulo, tamanho_modulo },
                           (struct bytes){ prova, tamanho_prova });
}

enum resultado_merkle verificar_prova_complementar(
    const struct raiz_merkle *raiz, const struct folha_complementar *folha,
    struct bytes modulo, struct bytes prova)
{
    return verificar_prova(raiz, folha, modulo, prova);
}
