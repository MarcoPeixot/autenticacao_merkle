#define _POSIX_C_SOURCE 200809L

#include "arquivos.h"
#include "mrauth.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const motivos[] = {
    [MERKLE_OK] = "OK",
    [MERKLE_ENOPKG] = "ENOPKG",
    [MERKLE_ENOKEY] = "ENOKEY",
    [MERKLE_ERRO_CRIPTOGRAFICO] = "ERRO_CRIPTOGRAFICO",
    [MERKLE_FORMATO_INVALIDO] = "FORMATO_INVALIDO",
    [MERKLE_POSICAO_INVALIDA] = "POSICAO_INVALIDA",
    [MERKLE_AUTORIDADE_NAO_AUTORIZADA] = "AUTORIDADE_NAO_AUTORIZADA",
    [MERKLE_ASSINATURA_INVALIDA] = "ASSINATURA_INVALIDA",
    [MERKLE_KERNEL_INCOMPATIVEL] = "KERNEL_INCOMPATIVEL",
    [MERKLE_COMPONENTE_NAO_AUTORIZADO] = "COMPONENTE_NAO_AUTORIZADO",
    [MERKLE_PERMISSAO_NEGADA] = "PERMISSAO_NEGADA",
    [MERKLE_ROLLBACK] = "ROLLBACK",
    [MERKLE_REVOGADO] = "REVOGADO",
    [MERKLE_REVOGACAO_REGRESSIVA] = "REVOGACAO_REGRESSIVA",
    [MERKLE_ESTADO_EXISTENTE] = "ESTADO_EXISTENTE",
    [MERKLE_ERRO_PERSISTENCIA] = "ERRO_PERSISTENCIA",
};

static bool ler_decimal(const char *texto, uint64_t limite, uint64_t *saida)
{
    if (texto[0] < '0' || texto[0] > '9')
        return false;

    char *fim;
    errno = 0;
    uintmax_t valor = strtoumax(texto, &fim, 10);
    if (*fim != '\0' || errno || valor > limite)
        return false;
    *saida = (uint64_t)valor;
    return true;
}

static int valor_hex(unsigned char caractere)
{
    if (caractere >= '0' && caractere <= '9')
        return caractere - '0';

    int letra = tolower(caractere);
    if (letra >= 'a' && letra <= 'f')
        return letra - 'a' + 10;
    return -1;
}

static bool decodificar_hex(char *texto, size_t *tamanho)
{
    if (strcmp(texto, "-") == 0) {
        *tamanho = 0;
        return true;
    }

    const size_t caracteres = strlen(texto);
    if (caracteres % 2 != 0)
        return false;

    unsigned char *bytes = (unsigned char *)texto;
    for (size_t i = 0; i < caracteres / 2; i++) {
        int alto = valor_hex(bytes[2 * i]);
        int baixo = valor_hex(bytes[2 * i + 1]);
        if (alto < 0 || baixo < 0)
            return false;
        bytes[i] = (unsigned char)((alto << 4) | baixo);
    }
    *tamanho = caracteres / 2;
    return true;
}

static const char *verificar_linha(char *linha)
{
    const char *separadores = " \t\r\n";
    char *restante;
    char *niveis = strtok_r(linha, separadores, &restante);
    char *hash = strtok_r(NULL, separadores, &restante);
    char *modulo = strtok_r(NULL, separadores, &restante);
    char *prova = strtok_r(NULL, separadores, &restante);
    if (prova == NULL || strtok_r(NULL, separadores, &restante) != NULL)
        return NULL;

    uint64_t valor;
    if (!ler_decimal(niveis, UINT32_MAX, &valor))
        return NULL;

    struct raiz_merkle raiz = { .niveis = (uint32_t)valor };
    size_t tamanho_hash, tamanho_modulo, tamanho_prova;
    if (!decodificar_hex(hash, &tamanho_hash) || tamanho_hash != sizeof(raiz.hash) ||
        !decodificar_hex(modulo, &tamanho_modulo) || !decodificar_hex(prova, &tamanho_prova))
        return NULL;

    memcpy(raiz.hash, hash, sizeof(raiz.hash));
    enum resultado_merkle resultado = verificar_raiz_unica(
        &raiz, (const unsigned char *)modulo, tamanho_modulo,
        (const unsigned char *)prova, tamanho_prova);

    return motivos[resultado];
}

static int verificar_principais(void)
{
    char *linha = NULL;
    size_t capacidade = 0;
    size_t numero = 0;
    int status = EXIT_SUCCESS;
    ssize_t lidos;

    while ((lidos = getline(&linha, &capacidade, stdin)) >= 0) {
        numero++;
        const char *resultado = memchr(linha, '\0', (size_t)lidos) == NULL
            ? verificar_linha(linha) : NULL;
        if (resultado == NULL) {
            fprintf(stderr, "linha %zu: entrada inválida\n", numero);
            status = EXIT_FAILURE;
            break;
        }
        if (puts(resultado) == EOF) {
            status = EXIT_FAILURE;
            break;
        }
    }

    if (!feof(stdin) || fflush(stdout) == EOF)
        status = EXIT_FAILURE;
    free(linha);
    return status;
}

static struct bytes bytes_de(const struct buffer *buffer)
{
    return (struct bytes){ buffer->dados, buffer->tamanho };
}

static int imprimir_decisao(struct decisao_mrauth decisao)
{
    if (decisao.autoridade == 0) {
        printf("%s - -\n", motivos[decisao.motivo]);
    } else {
        printf("%s ", motivos[decisao.motivo]);
        for (size_t i = 0; i < sizeof(decisao.raiz.hash); i++)
            printf("%02x", (unsigned)decisao.raiz.hash[i]);
        printf(" %" PRIu32 "\n", decisao.autoridade);
    }
    return fflush(stdout) == 0 && decisao.motivo == MERKLE_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int verificar_com_arquivos(char **argv)
{
    size_t tamanho_kernel;
    uint64_t componente, geracao;
    if (!decodificar_hex(argv[4], &tamanho_kernel) || tamanho_kernel != HASH_BYTES ||
        !ler_decimal(argv[6], UINT32_MAX, &componente) || !ler_decimal(argv[7], UINT64_MAX, &geracao))
        return imprimir_decisao((struct decisao_mrauth){ .motivo = MERKLE_FORMATO_INVALIDO });

    struct buffer politica = {0}, manifesto = {0}, modulo = {0}, prova = {0};
    struct buffer estado = {0}, novo = {0};
    struct decisao_mrauth decisao = { .motivo = MERKLE_ERRO_PERSISTENCIA };
    int trava = -1;
    if (ler_arquivo(argv[2], &politica) && ler_arquivo(argv[5], &manifesto) &&
        ler_arquivo(argv[8], &modulo) && ler_arquivo(argv[9], &prova)) {
        trava = travar_estado(argv[3]);
        if (trava >= 0 && ler_arquivo(argv[3], &estado)) {
            struct entrada_mrauth entrada = {
                .kernel = (const unsigned char *)argv[4],
                .manifesto = bytes_de(&manifesto), .modulo = bytes_de(&modulo), .prova = bytes_de(&prova),
                .componente = (uint32_t)componente, .geracao = geracao,
            };
            decisao = verificar_complementar(bytes_de(&politica), bytes_de(&estado), &entrada, &novo);
            if (novo.dados && !gravar_estado(argv[3], &novo))
                decisao.motivo = MERKLE_ERRO_PERSISTENCIA;
        }
    }
    if (trava >= 0)
        close(trava);
    free(novo.dados);
    free(estado.dados);
    free(prova.dados);
    free(modulo.dados);
    free(manifesto.dados);
    free(politica.dados);
    return imprimir_decisao(decisao);
}

static enum resultado_merkle provisionar(const char *caminho, struct bytes politica,
                                         struct bytes tabela, struct buffer *novo)
{
    struct stat info;
    if (lstat(caminho, &info) == 0)
        return MERKLE_ESTADO_EXISTENTE;
    if (errno != ENOENT)
        return MERKLE_ERRO_PERSISTENCIA;
    return iniciar_estado(politica, tabela, novo);
}

static int gerenciar_estado(char **argv, bool iniciar)
{
    struct buffer politica = {0}, estado = {0}, tabela = {0}, novo = {0};
    enum resultado_merkle motivo = MERKLE_ERRO_PERSISTENCIA;
    int trava = -1;
    if (ler_arquivo(argv[2], &politica) && ler_arquivo(argv[4], &tabela)) {
        trava = travar_estado(argv[3]);
        if (trava >= 0) {
            if (iniciar)
                motivo = provisionar(argv[3], bytes_de(&politica), bytes_de(&tabela), &novo);
            else if (ler_arquivo(argv[3], &estado))
                motivo = atualizar_revogacao(bytes_de(&politica), bytes_de(&estado), bytes_de(&tabela), &novo);
            if (novo.dados && !gravar_estado(argv[3], &novo))
                motivo = MERKLE_ERRO_PERSISTENCIA;
        }
    }
    if (trava >= 0)
        close(trava);
    free(novo.dados);
    free(tabela.dados);
    free(estado.dados);
    free(politica.dados);
    return imprimir_decisao((struct decisao_mrauth){ .motivo = motivo });
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return verificar_principais();
    if (argc == 10 && strcmp(argv[1], "complementar") == 0)
        return verificar_com_arquivos(argv);
    if (argc == 5) {
        if (strcmp(argv[1], "iniciar") == 0)
            return gerenciar_estado(argv, true);
        if (strcmp(argv[1], "revogar") == 0)
            return gerenciar_estado(argv, false);
    }
    fprintf(stderr, "Uso: %s [iniciar|revogar politica estado tabela]\n"
                    "     %s complementar politica estado kernel_hex manifesto componente geracao modulo prova\n",
            argv[0], argv[0]);
    return EXIT_FAILURE;
}
