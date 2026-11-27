#ifndef AUTENTICACAO_MRAUTH_H
#define AUTENTICACAO_MRAUTH_H

#include "merkle.h"

struct entrada_mrauth {
    const unsigned char *kernel;
    struct bytes manifesto;
    struct bytes modulo;
    struct bytes prova;
    uint32_t componente;
    uint64_t geracao;
};

struct decisao_mrauth {
    enum resultado_merkle motivo;
    uint32_t autoridade;
    struct raiz_merkle raiz;
};

struct decisao_mrauth verificar_complementar(
    struct bytes politica, struct bytes estado, const struct entrada_mrauth *entrada,
    struct buffer *estado_novo);

enum resultado_merkle iniciar_estado(
    struct bytes politica, struct bytes tabela, struct buffer *estado_novo);

enum resultado_merkle atualizar_revogacao(
    struct bytes politica, struct bytes estado, struct bytes tabela, struct buffer *estado_novo);

#endif
