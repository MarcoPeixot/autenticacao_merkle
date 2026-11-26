/*
 * Roda o module_hash_check() de patch-v5/kernel/module/hashes.c em espaço
 * de usuário.
 *
 * Lê um caso por linha na entrada padrão:
 *
 *     níveis  raiz  módulo  prova
 *
 * com raiz, módulo e prova em hexadecimal ("-" quando vazio), e escreve uma
 * linha com OK, ENOPKG, ENOKEY ou o código devolvido.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * hashes.c lê a raiz em "extern const struct module_hashes_root". Aqui ela é
 * definida com o mesmo leiaute (u32 seguido de 32 bytes) e sem const, para
 * cada caso trazer a sua.
 */
struct raiz {
	uint32_t levels;
	uint8_t hash[32];
};

struct raiz module_hashes_root;

int module_hash_check(const void *mod, size_t mod_len, const void *sig, size_t sig_len);

static size_t de_hex(const char *texto, uint8_t **saida)
{
	size_t n;

	*saida = NULL;
	if (strcmp(texto, "-") == 0)
		return 0;

	n = strlen(texto);
	if (n % 2) {
		fprintf(stderr, "hexadecimal com tamanho ímpar\n");
		exit(1);
	}
	*saida = malloc(n / 2);
	if (!*saida)
		exit(1);
	for (size_t i = 0; i < n / 2; i++) {
		unsigned int byte;

		if (sscanf(texto + 2 * i, "%2x", &byte) != 1) {
			fprintf(stderr, "hexadecimal inválido\n");
			exit(1);
		}
		(*saida)[i] = (uint8_t)byte;
	}
	return n / 2;
}

int main(void)
{
	char *linha = NULL;
	size_t capacidade = 0;

	while (getline(&linha, &capacidade, stdin) != -1) {
		char raiz_hex[128], *modulo_hex, *prova_hex;
		uint8_t *raiz, *modulo, *prova;
		size_t tamanho_raiz, tamanho_modulo, tamanho_prova;
		unsigned int niveis;
		int resposta;

		modulo_hex = malloc(strlen(linha) + 1);
		prova_hex = malloc(strlen(linha) + 1);
		if (!modulo_hex || !prova_hex)
			exit(1);
		if (sscanf(linha, "%u %127s %s %s", &niveis, raiz_hex, modulo_hex, prova_hex) != 4) {
			fprintf(stderr, "linha inválida: %s", linha);
			return 1;
		}

		tamanho_raiz = de_hex(raiz_hex, &raiz);
		if (tamanho_raiz != sizeof(module_hashes_root.hash)) {
			fprintf(stderr, "raiz precisa ter 32 bytes\n");
			return 1;
		}
		tamanho_modulo = de_hex(modulo_hex, &modulo);
		tamanho_prova = de_hex(prova_hex, &prova);

		module_hashes_root.levels = niveis;
		memcpy(module_hashes_root.hash, raiz, tamanho_raiz);

		resposta = module_hash_check(modulo, tamanho_modulo, prova, tamanho_prova);
		if (resposta == 0)
			puts("OK");
		else if (resposta == -ENOPKG)
			puts("ENOPKG");
		else if (resposta == -ENOKEY)
			puts("ENOKEY");
		else
			printf("%d\n", resposta);

		free(raiz);
		free(modulo);
		free(prova);
		free(modulo_hex);
		free(prova_hex);
	}
	free(linha);
	return 0;
}
