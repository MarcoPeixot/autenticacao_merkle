#ifndef AUTENTICACAO_BYTES_H
#define AUTENTICACAO_BYTES_H

#include <stddef.h>
#include <stdint.h>

struct bytes {
    const unsigned char *dados;
    size_t tamanho;
};

struct buffer {
    unsigned char *dados;
    size_t tamanho;
};

static inline uint32_t ler_u32(const unsigned char *dados)
{
    return ((uint32_t)dados[0] << 24) | ((uint32_t)dados[1] << 16) |
           ((uint32_t)dados[2] << 8) | dados[3];
}

static inline uint64_t ler_u64(const unsigned char *dados)
{
    return ((uint64_t)ler_u32(dados) << 32) | ler_u32(dados + 4);
}

static inline void gravar_u32(unsigned char *dados, uint32_t valor)
{
    dados[0] = (unsigned char)(valor >> 24);
    dados[1] = (unsigned char)(valor >> 16);
    dados[2] = (unsigned char)(valor >> 8);
    dados[3] = (unsigned char)valor;
}

static inline void gravar_u64(unsigned char *dados, uint64_t valor)
{
    gravar_u32(dados, (uint32_t)(valor >> 32));
    gravar_u32(dados + 4, (uint32_t)valor);
}

#endif
