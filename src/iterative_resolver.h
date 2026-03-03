#ifndef ITERATIVE_RESOLVER_H
#define ITERATIVE_RESOLVER_H

#include <stdint.h>

int iterative_resolve_a(const char *hostname, int timeout_ms, uint32_t *addr_v4_be_out);

#endif
