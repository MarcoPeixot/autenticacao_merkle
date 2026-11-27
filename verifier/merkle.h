#ifndef AUTENTICACAO_MERKLE_H
#define AUTENTICACAO_MERKLE_H

#include <stddef.h>
#include <stdint.h>

#include "bytes.h"

enum { HASH_BYTES = 32 };

struct raiz_merkle {
    uint32_t niveis;
    unsigned char hash[HASH_BYTES];
};

enum resultado_merkle {
    MERKLE_OK,
    MERKLE_ENOPKG,
    MERKLE_ENOKEY,
    MERKLE_ERRO_CRIPTOGRAFICO,
    MERKLE_FORMATO_INVALIDO,
    MERKLE_POSICAO_INVALIDA,
    MERKLE_AUTORIDADE_NAO_AUTORIZADA,
    MERKLE_ASSINATURA_INVALIDA,
    MERKLE_KERNEL_INCOMPATIVEL,
    MERKLE_COMPONENTE_NAO_AUTORIZADO,
    MERKLE_PERMISSAO_NEGADA,
    MERKLE_ROLLBACK,
    MERKLE_REVOGADO,
    MERKLE_REVOGACAO_REGRESSIVA,
    MERKLE_ESTADO_EXISTENTE,
    MERKLE_ERRO_PERSISTENCIA,
};

struct folha_complementar {
    uint32_t arvore;
    uint32_t numero_folhas;
    uint32_t componente;
    uint64_t geracao;
};

enum resultado_merkle verificar_raiz_unica(
    const struct raiz_merkle *raiz,
    const unsigned char *modulo, size_t tamanho_modulo,
    const unsigned char *prova, size_t tamanho_prova);

enum resultado_merkle verificar_prova_complementar(
    const struct raiz_merkle *raiz, const struct folha_complementar *folha,
    struct bytes modulo, struct bytes prova);

#endif
