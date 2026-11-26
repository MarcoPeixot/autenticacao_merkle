/* Do kernel/module/internal.h só interessa a declaração do verificador. */
#ifndef APOIO_INTERNAL_H
#define APOIO_INTERNAL_H

#include <stddef.h>

int module_hash_check(const void *mod, size_t mod_len, const void *sig, size_t sig_len);

#endif
