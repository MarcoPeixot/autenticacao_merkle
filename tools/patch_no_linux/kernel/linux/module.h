/* O que hashes.c usa de <linux/module.h> e do resto do kernel. */
#ifndef APOIO_LINUX_MODULE_H
#define APOIO_LINUX_MODULE_H

#define _DEFAULT_SOURCE 1
#include <endian.h>
#include <errno.h>
#include <string.h>

#include <linux/types.h>

#define __init
#define __maybe_unused __attribute__((unused))
#define IS_ENABLED(opcao) 0
#define early_initcall(funcao)
#define pr_debug(...) do { } while (0)

#define cpu_to_be32(x) htobe32(x)

/* include/linux/overflow.h, sem a proteção contra estouro. */
#define struct_size(p, membro, n) (sizeof(*(p)) + sizeof((p)->membro[0]) * (n))

#endif
