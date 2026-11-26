/* A interface sha256_* do kernel, por cima do OpenSSL. */
#ifndef APOIO_CRYPTO_SHA2_H
#define APOIO_CRYPTO_SHA2_H

#include <stdlib.h>

#include <openssl/evp.h>

#include <linux/types.h>

#define SHA256_DIGEST_SIZE 32

struct sha256_ctx {
	EVP_MD_CTX *md;
};

static inline void sha256_init(struct sha256_ctx *ctx)
{
	ctx->md = EVP_MD_CTX_new();
	if (!ctx->md || EVP_DigestInit_ex(ctx->md, EVP_sha256(), NULL) != 1)
		abort();
}

static inline void sha256_update(struct sha256_ctx *ctx, const u8 *dados, size_t tamanho)
{
	if (EVP_DigestUpdate(ctx->md, dados, tamanho) != 1)
		abort();
}

static inline void sha256_final(struct sha256_ctx *ctx, u8 *saida)
{
	if (EVP_DigestFinal_ex(ctx->md, saida, NULL) != 1)
		abort();
	EVP_MD_CTX_free(ctx->md);
}

#endif
