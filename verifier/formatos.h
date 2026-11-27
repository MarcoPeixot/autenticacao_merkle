#ifndef AUTENTICACAO_FORMATOS_H
#define AUTENTICACAO_FORMATOS_H

#include <stdbool.h>

#include "merkle.h"

enum { MANIFESTO_BYTES = 98, REGISTRO_BYTES = 12 };

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
uint64_t valor_registro(const struct registros *lista, uint32_t id);
bool montar_estado(struct bytes tabela, const struct registros *versoes,
                   uint32_t arvore, uint64_t versao, struct buffer *saida);

#endif
