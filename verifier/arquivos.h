#ifndef AUTENTICACAO_ARQUIVOS_H
#define AUTENTICACAO_ARQUIVOS_H

#include <stdbool.h>

#include "bytes.h"

bool ler_arquivo(const char *caminho, struct buffer *saida);
int travar_estado(const char *caminho);
bool gravar_estado(const char *caminho, const struct buffer *estado);

#endif
