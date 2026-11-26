/* Leitura de 32 bits big-endian sem exigir alinhamento. */
#ifndef APOIO_LINUX_UNALIGNED_H
#define APOIO_LINUX_UNALIGNED_H

#define _DEFAULT_SOURCE 1
#include <endian.h>
#include <stdint.h>
#include <string.h>

static inline uint32_t get_unaligned_be32(const void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return be32toh(v);
}

#endif
