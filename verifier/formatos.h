#ifndef AUTENTICACAO_FORMATOS_H
#define AUTENTICACAO_FORMATOS_H

#include <stdbool.h>

#include "merkle.h"

/* Geração mínima: componente:u32 || geração:u64.
 * Versão de árvore: árvore:u32 || versão:u64 || SHA-256 dos bytes assinados do manifesto. */
enum {
    MANIFESTO_BYTES = 98,
    GERACAO_BYTES = 12,
    VERSAO_RESUMO = 12,
    VERSAO_BYTES = VERSAO_RESUMO + HASH_BYTES,
};

struct conjunto_ml_dsa {
    unsigned char id;
    const char *nome;
    size_t chave_bytes;
    size_t assinatura_bytes;
};

struct manifesto {
    uint32_t arvore;
    uint32_t autoridade;
    uint64_t versao;
    const unsigned char *kernel;
    uint32_t numero_folhas;
    struct raiz_merkle raiz;
    uint64_t permissoes;
};

struct politica_mrauth {
    const struct conjunto_ml_dsa *conjunto;
    const unsigned char *chave_revogacao;
    const unsigned char *chave_autoridade;
    const unsigned char *autorizacao;
    bool autoriza_arvore;
    bool arvore_ambigua;
};

struct registros {
    const unsigned char *dados;
    uint32_t quantidade;
    size_t largura;
};

struct tabela_revogacao {
    struct bytes bruta;
    struct registros geracoes;
    uint64_t versao;
};

struct estado_mrauth {
    struct tabela_revogacao revogacao;
    struct registros versoes;
};

bool ler_manifesto(struct bytes bruto, struct manifesto *saida);
bool ler_politica(struct bytes bruto, const struct manifesto *manifesto, uint32_t componente,
                  struct politica_mrauth *saida);
bool ler_revogacao(struct bytes bruto, size_t assinatura_bytes, struct tabela_revogacao *saida);
bool ler_estado(struct bytes bruto, size_t assinatura_bytes, struct estado_mrauth *saida);
const unsigned char *buscar_registro(const struct registros *lista, uint32_t id);
uint64_t valor_registro(const struct registros *lista, uint32_t id);
bool montar_estado(struct bytes tabela, const struct registros *versoes, uint32_t arvore,
                   uint64_t versao, const unsigned char *resumo, struct buffer *saida);

#endif
