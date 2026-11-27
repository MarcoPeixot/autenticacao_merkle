#define _POSIX_C_SOURCE 200809L

#include "arquivos.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool ler_arquivo(const char *caminho, struct buffer *saida)
{
    FILE *arquivo = fopen(caminho, "rb");
    if (arquivo == NULL)
        return false;

    struct stat info;
    unsigned char *dados = NULL;
    size_t tamanho = 0;
    bool ok = false;
    if (fstat(fileno(arquivo), &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size >= 0 && (uintmax_t)info.st_size <= SIZE_MAX) {
        tamanho = (size_t)info.st_size;
        dados = malloc(tamanho ? tamanho : 1);
        ok = dados && fread(dados, 1, tamanho, arquivo) == tamanho &&
             fgetc(arquivo) == EOF && !ferror(arquivo);
    }
    if (fclose(arquivo) != 0)
        ok = false;
    if (!ok) {
        free(dados);
        return false;
    }
    *saida = (struct buffer){ dados, tamanho };
    return true;
}

static char *com_sufixo(const char *caminho, const char *sufixo)
{
    size_t base = strlen(caminho), restante = strlen(sufixo) + 1;
    if (base > SIZE_MAX - restante)
        return NULL;

    char *nome = malloc(base + restante);
    if (nome) {
        memcpy(nome, caminho, base);
        memcpy(nome + base, sufixo, restante);
    }
    return nome;
}

int travar_estado(const char *caminho)
{
    char *nome = com_sufixo(caminho, ".lock");
    if (nome == NULL)
        return -1;

    int fd = open(nome, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    free(nome);
    if (fd < 0)
        return -1;

    struct flock bloqueio = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    int resultado;
    do {
        resultado = fcntl(fd, F_SETLKW, &bloqueio);
    } while (resultado < 0 && errno == EINTR);
    if (resultado != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int abrir_diretorio(const char *caminho)
{
    const char *barra = strrchr(caminho, '/');
    if (barra == NULL)
        return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (barra == caminho)
        return open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    char *diretorio = strndup(caminho, (size_t)(barra - caminho));
    if (diretorio == NULL)
        return -1;
    int fd = open(diretorio, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(diretorio);
    return fd;
}

bool gravar_estado(const char *caminho, const struct buffer *estado)
{
    int diretorio = abrir_diretorio(caminho);
    if (diretorio < 0)
        return false;

    char *temporario = com_sufixo(caminho, ".tmp.XXXXXX");
    int fd = temporario ? mkstemp(temporario) : -1;
    bool ok = false;
    if (fd >= 0) {
        FILE *arquivo = fdopen(fd, "wb");
        if (arquivo) {
            ok = fwrite(estado->dados, 1, estado->tamanho, arquivo) == estado->tamanho &&
                 fflush(arquivo) == 0 && fsync(fd) == 0;
            if (fclose(arquivo) != 0)
                ok = false;
        } else {
            close(fd);
        }
        if (ok && rename(temporario, caminho) == 0)
            ok = fsync(diretorio) == 0;
        else {
            unlink(temporario);
            ok = false;
        }
    }
    free(temporario);
    close(diretorio);
    return ok;
}
