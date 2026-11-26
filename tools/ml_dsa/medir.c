/*
 * Mede o ML-DSA do OpenSSL nos três conjuntos do FIPS 204: tamanhos,
 * checagens de recusa e tempo de gerar a chave, assinar e verificar.
 *
 * Uso: medir <rodadas>
 *
 * Saída, uma linha por item, lida por tools/medir_ml_dsa.py:
 *   tamanho <conjunto> <chave pública> <chave privada> <assinatura>
 *   checagem <conjunto> <caso> <aceita|recusa>
 *   tempo <conjunto> <operação> <µs por operação em cada rodada...>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define CONJUNTOS 3
#define MENSAGEM 128 /* ordem de grandeza de um manifesto, que ainda não tem formato */
#define MAX_ASSINATURA 8192
#define MAX_CHAVE 8192
#define MAX_RODADAS 1000

static const char *nomes[CONJUNTOS] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" };

/* Cada rodada cronometra um lote de operações e divide pelo tamanho do lote. */
enum { GERAR, ASSINAR, VERIFICAR, OPERACOES };
static const char *operacoes[OPERACOES] = { "gerar", "assinar", "verificar" };
static const int lote[OPERACOES] = { 50, 100, 200 };

static double tempos[CONJUNTOS][OPERACOES][MAX_RODADAS];

static void falhou(const char *onde)
{
	fprintf(stderr, "falhou: %s\n", onde);
	ERR_print_errors_fp(stderr);
	exit(1);
}

static double agora_us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static void mensagem(unsigned char *msg)
{
	for (int i = 0; i < MENSAGEM; i++)
		msg[i] = (unsigned char)i;
}

static EVP_PKEY *gerar(const char *conjunto)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, conjunto, NULL);
	EVP_PKEY *chave = NULL;

	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &chave) <= 0)
		falhou("gerar a chave");
	EVP_PKEY_CTX_free(ctx);
	return chave;
}

/* Só a parte pública, importada dos bytes, que é o que o verificador recebe. */
static EVP_PKEY *so_publica(const char *conjunto, EVP_PKEY *par, size_t *tamanho)
{
	unsigned char bytes[MAX_CHAVE];
	EVP_PKEY *publica;

	if (EVP_PKEY_get_octet_string_param(par, OSSL_PKEY_PARAM_PUB_KEY, bytes, sizeof(bytes), tamanho) <= 0)
		falhou("ler a chave pública");
	publica = EVP_PKEY_new_raw_public_key_ex(NULL, conjunto, NULL, bytes, *tamanho);
	if (!publica)
		falhou("importar a chave pública");
	return publica;
}

static size_t assinar(EVP_SIGNATURE *alg, EVP_PKEY *chave, const unsigned char *msg, size_t n,
		      unsigned char *assinatura)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, chave, NULL);
	size_t tamanho = MAX_ASSINATURA;

	if (!ctx || EVP_PKEY_sign_message_init(ctx, alg, NULL) <= 0 ||
	    EVP_PKEY_sign(ctx, assinatura, &tamanho, msg, n) <= 0)
		falhou("assinar");
	EVP_PKEY_CTX_free(ctx);
	return tamanho;
}

/* 1 se a assinatura passa, 0 em qualquer outro caso. */
static int verificar(EVP_SIGNATURE *alg, EVP_PKEY *chave, const unsigned char *msg, size_t n,
		     const unsigned char *assinatura, size_t tamanho)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, chave, NULL);
	int r;

	if (!ctx || EVP_PKEY_verify_message_init(ctx, alg, NULL) <= 0)
		falhou("preparar a verificação");
	r = EVP_PKEY_verify(ctx, assinatura, tamanho, msg, n);
	EVP_PKEY_CTX_free(ctx);
	ERR_clear_error();
	return r == 1;
}

static void checagem(const char *conjunto, const char *caso, int aceita)
{
	printf("checagem %s %s %s\n", conjunto, caso, aceita ? "aceita" : "recusa");
}

static void checar(const char *conjunto, EVP_SIGNATURE *alg)
{
	unsigned char msg[MENSAGEM], outra[MENSAGEM];
	unsigned char assinatura[MAX_ASSINATURA], alterada[MAX_ASSINATURA], privada[MAX_CHAVE];
	size_t tam_publica, tam_outra, tam_privada, tam;
	EVP_PKEY *par = gerar(conjunto), *outro_par = gerar(conjunto);
	EVP_PKEY *publica = so_publica(conjunto, par, &tam_publica);
	EVP_PKEY *outra_publica = so_publica(conjunto, outro_par, &tam_outra);

	if (EVP_PKEY_get_octet_string_param(par, OSSL_PKEY_PARAM_PRIV_KEY, privada, sizeof(privada),
					    &tam_privada) <= 0)
		falhou("ler a chave privada");

	mensagem(msg);
	tam = assinar(alg, par, msg, sizeof(msg), assinatura);
	printf("tamanho %s %zu %zu %zu\n", conjunto, tam_publica, tam_privada, tam);

	checagem(conjunto, "valida", verificar(alg, publica, msg, sizeof(msg), assinatura, tam));

	memcpy(outra, msg, sizeof(msg));
	outra[0] ^= 1;
	checagem(conjunto, "mensagem_alterada", verificar(alg, publica, outra, sizeof(outra), assinatura, tam));

	memcpy(alterada, assinatura, tam);
	alterada[tam / 2] ^= 1;
	checagem(conjunto, "assinatura_alterada", verificar(alg, publica, msg, sizeof(msg), alterada, tam));

	checagem(conjunto, "assinatura_cortada", verificar(alg, publica, msg, sizeof(msg), assinatura, tam - 1));

	checagem(conjunto, "outra_chave", verificar(alg, outra_publica, msg, sizeof(msg), assinatura, tam));

	EVP_PKEY_free(par);
	EVP_PKEY_free(outro_par);
	EVP_PKEY_free(publica);
	EVP_PKEY_free(outra_publica);
}

static void medir(int c, EVP_SIGNATURE *alg, int rodada)
{
	unsigned char msg[MENSAGEM], assinatura[MAX_ASSINATURA];
	size_t tam_publica, tam = 0;
	EVP_PKEY *par, *publica;
	double inicio;
	int i;

	mensagem(msg);

	inicio = agora_us();
	for (i = 0; i < lote[GERAR]; i++)
		EVP_PKEY_free(gerar(nomes[c]));
	tempos[c][GERAR][rodada] = (agora_us() - inicio) / lote[GERAR];

	par = gerar(nomes[c]);
	publica = so_publica(nomes[c], par, &tam_publica);

	inicio = agora_us();
	for (i = 0; i < lote[ASSINAR]; i++)
		tam = assinar(alg, par, msg, sizeof(msg), assinatura);
	tempos[c][ASSINAR][rodada] = (agora_us() - inicio) / lote[ASSINAR];

	inicio = agora_us();
	for (i = 0; i < lote[VERIFICAR]; i++)
		if (!verificar(alg, publica, msg, sizeof(msg), assinatura, tam))
			falhou("verificar a assinatura do lote");
	tempos[c][VERIFICAR][rodada] = (agora_us() - inicio) / lote[VERIFICAR];

	EVP_PKEY_free(par);
	EVP_PKEY_free(publica);
}

int main(int argc, char **argv)
{
	EVP_SIGNATURE *alg[CONJUNTOS];
	int rodadas, r, c, o;

	if (argc != 2 || (rodadas = atoi(argv[1])) < 1 || rodadas > MAX_RODADAS) {
		fprintf(stderr, "uso: %s <rodadas, de 1 a %d>\n", argv[0], MAX_RODADAS);
		return 2;
	}

	for (c = 0; c < CONJUNTOS; c++) {
		alg[c] = EVP_SIGNATURE_fetch(NULL, nomes[c], NULL);
		if (!alg[c])
			falhou("achar o algoritmo");
		checar(nomes[c], alg[c]);
	}

	/* Uma rodada de aquecimento, fora da conta. Depois os conjuntos se alternam. */
	for (c = 0; c < CONJUNTOS; c++)
		medir(c, alg[c], 0);
	for (r = 0; r < rodadas; r++)
		for (c = 0; c < CONJUNTOS; c++)
			medir(c, alg[c], r);

	for (c = 0; c < CONJUNTOS; c++) {
		for (o = 0; o < OPERACOES; o++) {
			printf("tempo %s %s", nomes[c], operacoes[o]);
			for (r = 0; r < rodadas; r++)
				printf(" %.2f", tempos[c][o][r]);
			printf("\n");
		}
		EVP_SIGNATURE_free(alg[c]);
	}
	return 0;
}
