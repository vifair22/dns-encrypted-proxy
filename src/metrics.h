#ifndef METRICS_H
#define METRICS_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct {
    atomic_uint_fast64_t queries_udp;
    atomic_uint_fast64_t queries_tcp;
    atomic_uint_fast64_t cache_hits;
    atomic_uint_fast64_t cache_misses;
    atomic_uint_fast64_t upstream_success;
    atomic_uint_fast64_t upstream_failures;
    atomic_uint_fast64_t servfail_sent;
    atomic_uint_fast64_t truncated_sent;
    atomic_uint_fast64_t tcp_connections_total;
    atomic_uint_fast64_t tcp_connections_rejected;
    atomic_int_fast32_t tcp_connections_active;
} proxy_metrics_t;

void metrics_init(proxy_metrics_t *m);
int metrics_server_start(proxy_metrics_t *m, int port);
void metrics_server_stop(void);

#endif
