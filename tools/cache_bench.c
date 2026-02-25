#define _POSIX_C_SOURCE 200809L

#include "cache.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    size_t capacity;
    size_t preload;
    size_t operations;
    size_t lookups;
    size_t stores;
    size_t misses;
    double seconds;
    uint64_t evictions;
    uint64_t expirations;
    size_t bytes_in_use;
} bench_result_t;

typedef struct {
    size_t depth_entries;
    size_t lookups;
    size_t hit_count;
    size_t miss_count;
    double avg_lookup_us;
    double avg_hit_lookup_us;
    double avg_miss_lookup_us;
} depth_latency_t;

typedef struct {
    size_t capacity;
    size_t threads;
    size_t operations;
    size_t lookups;
    size_t stores;
    size_t misses;
    double seconds;
    uint64_t evictions;
    uint64_t expirations;
} threaded_result_t;

typedef struct {
    dns_cache_t *cache;
    atomic_uint_fast64_t *next_id;
    size_t operations;
    uint64_t seed;
    size_t lookups;
    size_t stores;
    size_t misses;
    uint8_t request_id[2];
} threaded_worker_args_t;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void make_key(uint64_t id, uint8_t key[12]) {
    key[0] = 0xAB;
    key[1] = 0xCD;
    key[2] = 0xEF;
    key[3] = 0x01;
    key[4] = (uint8_t)((id >> 56) & 0xFFu);
    key[5] = (uint8_t)((id >> 48) & 0xFFu);
    key[6] = (uint8_t)((id >> 40) & 0xFFu);
    key[7] = (uint8_t)((id >> 32) & 0xFFu);
    key[8] = (uint8_t)((id >> 24) & 0xFFu);
    key[9] = (uint8_t)((id >> 16) & 0xFFu);
    key[10] = (uint8_t)((id >> 8) & 0xFFu);
    key[11] = (uint8_t)(id & 0xFFu);
}

static void make_response(uint64_t id, uint8_t response[12]) {
    memset(response, 0, 12);
    response[0] = 0x12;
    response[1] = 0x34;
    response[2] = 0x81;
    response[3] = 0x80;
    response[4] = 0x00;
    response[5] = 0x01;
    response[6] = 0x00;
    response[7] = 0x00;
    response[8] = 0x00;
    response[9] = 0x00;
    response[10] = 0x00;
    response[11] = (uint8_t)(id & 0xFFu);
}

static int run_bench(size_t capacity, size_t operations, bench_result_t *out) {
    if (out == NULL || capacity == 0 || operations == 0) {
        return -1;
    }

    dns_cache_t cache;
    if (dns_cache_init(&cache, capacity) != 0) {
        return -1;
    }

    uint64_t next_id = 1;
    size_t preload = capacity;
    if (preload > operations / 4) {
        preload = operations / 4;
    }
    if (preload < 1) {
        preload = 1;
    }

    for (size_t i = 0; i < preload; i++) {
        uint8_t key[12];
        uint8_t response[12];
        make_key(next_id, key);
        make_response(next_id, response);
        dns_cache_store(&cache, key, sizeof(key), response, sizeof(response), 300);
        next_id++;
    }

    uint64_t rng = 0xC0FFEE1234ULL ^ (uint64_t)capacity;
    const uint8_t request_id[2] = {0x55, 0xAA};
    size_t lookups = 0;
    size_t stores = 0;
    size_t misses = 0;

    uint64_t start = now_ns();
    for (size_t i = 0; i < operations; i++) {
        uint64_t r = xorshift64(&rng) % 100;
        if (r < 65) {
            uint64_t span = next_id > 1 ? (next_id - 1) : 1;
            uint64_t back = xorshift64(&rng) % span;
            uint64_t id = (next_id - 1) - back;
            uint8_t key[12];
            make_key(id, key);

            uint8_t *response = NULL;
            size_t response_len = 0;
            (void)dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
            free(response);
            lookups++;
        } else if (r < 85) {
            uint8_t key[12];
            uint8_t response[12];
            make_key(next_id, key);
            make_response(next_id, response);
            dns_cache_store(&cache, key, sizeof(key), response, sizeof(response), 300);
            next_id++;
            stores++;
        } else {
            uint8_t key[12];
            make_key(next_id + 10000000ULL + (uint64_t)i, key);
            uint8_t *response = NULL;
            size_t response_len = 0;
            (void)dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
            free(response);
            misses++;
        }
    }
    uint64_t end = now_ns();

    uint64_t evictions = 0;
    uint64_t expirations = 0;
    size_t bytes_in_use = 0;
    dns_cache_get_counters(&cache, &evictions, &expirations, &bytes_in_use);

    out->capacity = capacity;
    out->preload = preload;
    out->operations = operations;
    out->lookups = lookups;
    out->stores = stores;
    out->misses = misses;
    out->seconds = (double)(end - start) / 1e9;
    out->evictions = evictions;
    out->expirations = expirations;
    out->bytes_in_use = bytes_in_use;

    dns_cache_destroy(&cache);
    return 0;
}

static int run_depth_latency_sweep(size_t capacity, depth_latency_t *rows, size_t row_count) {
    if (rows == NULL || row_count == 0 || capacity == 0) {
        return -1;
    }

    const uint8_t request_id[2] = {0x55, 0xAA};
    const size_t lookups_per_depth = 12000;

    for (size_t row = 0; row < row_count; row++) {
        dns_cache_t cache;
        if (dns_cache_init(&cache, capacity) != 0) {
            return -1;
        }

        size_t depth = rows[row].depth_entries;
        if (depth > capacity) {
            depth = capacity;
        }
        if (depth < 1) {
            depth = 1;
        }

        for (size_t i = 0; i < depth; i++) {
            uint8_t key[12];
            uint8_t response[12];
            make_key((uint64_t)(i + 1), key);
            make_response((uint64_t)(i + 1), response);
            dns_cache_store(&cache, key, sizeof(key), response, sizeof(response), 300);
        }

        uint64_t rng = 0xA11CE123ULL ^ (uint64_t)capacity ^ (uint64_t)depth;
        uint64_t total_ns = 0;
        uint64_t hit_ns = 0;
        uint64_t miss_ns = 0;
        size_t hit_count = 0;
        size_t miss_count = 0;

        for (size_t i = 0; i < lookups_per_depth; i++) {
            uint8_t key[12];
            if ((xorshift64(&rng) % 100) < 80) {
                uint64_t id = (xorshift64(&rng) % (uint64_t)depth) + 1;
                make_key(id, key);
            } else {
                uint64_t id = (uint64_t)depth + 1000000ULL + (xorshift64(&rng) % 100000ULL);
                make_key(id, key);
            }

            uint64_t t0 = now_ns();
            uint8_t *response = NULL;
            size_t response_len = 0;
            int hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
            uint64_t t1 = now_ns();
            free(response);

            uint64_t dt = t1 - t0;
            total_ns += dt;
            if (hit) {
                hit_count++;
                hit_ns += dt;
            } else {
                miss_count++;
                miss_ns += dt;
            }
        }

        rows[row].depth_entries = depth;
        rows[row].lookups = lookups_per_depth;
        rows[row].hit_count = hit_count;
        rows[row].miss_count = miss_count;
        rows[row].avg_lookup_us = (double)total_ns / (double)lookups_per_depth / 1000.0;
        rows[row].avg_hit_lookup_us = hit_count > 0 ? ((double)hit_ns / (double)hit_count / 1000.0) : 0.0;
        rows[row].avg_miss_lookup_us = miss_count > 0 ? ((double)miss_ns / (double)miss_count / 1000.0) : 0.0;

        dns_cache_destroy(&cache);
    }

    return 0;
}

static void *threaded_worker_main(void *arg) {
    threaded_worker_args_t *w = (threaded_worker_args_t *)arg;
    if (w == NULL || w->cache == NULL || w->next_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < w->operations; i++) {
        uint64_t r = xorshift64(&w->seed) % 100;
        if (r < 65) {
            uint64_t span = atomic_load(w->next_id);
            if (span < 2) {
                span = 2;
            }
            uint64_t id = (xorshift64(&w->seed) % (span - 1)) + 1;
            uint8_t key[12];
            make_key(id, key);

            uint8_t *response = NULL;
            size_t response_len = 0;
            (void)dns_cache_lookup(w->cache, key, sizeof(key), w->request_id, &response, &response_len);
            free(response);
            w->lookups++;
        } else if (r < 85) {
            uint64_t id = atomic_fetch_add(w->next_id, 1);
            uint8_t key[12];
            uint8_t response[12];
            make_key(id, key);
            make_response(id, response);
            dns_cache_store(w->cache, key, sizeof(key), response, sizeof(response), 300);
            w->stores++;
        } else {
            uint64_t id = atomic_load(w->next_id) + 10000000ULL + (uint64_t)i;
            uint8_t key[12];
            make_key(id, key);

            uint8_t *response = NULL;
            size_t response_len = 0;
            (void)dns_cache_lookup(w->cache, key, sizeof(key), w->request_id, &response, &response_len);
            free(response);
            w->misses++;
        }
    }

    return NULL;
}

static int run_threaded_bench(size_t capacity, size_t operations, size_t threads, threaded_result_t *out) {
    if (out == NULL || capacity == 0 || operations == 0 || threads == 0) {
        return -1;
    }

    dns_cache_t cache;
    if (dns_cache_init(&cache, capacity) != 0) {
        return -1;
    }

    atomic_uint_fast64_t next_id;
    atomic_init(&next_id, 1);

    size_t preload = capacity;
    if (preload > operations / 4) {
        preload = operations / 4;
    }
    if (preload < 1) {
        preload = 1;
    }

    for (size_t i = 0; i < preload; i++) {
        uint64_t id = atomic_fetch_add(&next_id, 1);
        uint8_t key[12];
        uint8_t response[12];
        make_key(id, key);
        make_response(id, response);
        dns_cache_store(&cache, key, sizeof(key), response, sizeof(response), 300);
    }

    pthread_t *tids = calloc(threads, sizeof(*tids));
    threaded_worker_args_t *args = calloc(threads, sizeof(*args));
    if (tids == NULL || args == NULL) {
        free(tids);
        free(args);
        dns_cache_destroy(&cache);
        return -1;
    }

    size_t base_ops = operations / threads;
    size_t rem_ops = operations % threads;

    uint64_t start = now_ns();
    for (size_t i = 0; i < threads; i++) {
        args[i].cache = &cache;
        args[i].next_id = &next_id;
        args[i].operations = base_ops + (i < rem_ops ? 1 : 0);
        args[i].seed = 0xBEEFULL ^ ((uint64_t)capacity << 8) ^ (uint64_t)(i + 1);
        args[i].request_id[0] = (uint8_t)(i & 0xFFu);
        args[i].request_id[1] = (uint8_t)((i * 17u) & 0xFFu);
        if (pthread_create(&tids[i], NULL, threaded_worker_main, &args[i]) != 0) {
            for (size_t j = 0; j < i; j++) {
                pthread_join(tids[j], NULL);
            }
            free(tids);
            free(args);
            dns_cache_destroy(&cache);
            return -1;
        }
    }

    for (size_t i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }
    uint64_t end = now_ns();

    size_t lookups = 0;
    size_t stores = 0;
    size_t misses = 0;
    for (size_t i = 0; i < threads; i++) {
        lookups += args[i].lookups;
        stores += args[i].stores;
        misses += args[i].misses;
    }

    uint64_t evictions = 0;
    uint64_t expirations = 0;
    size_t bytes = 0;
    dns_cache_get_counters(&cache, &evictions, &expirations, &bytes);

    out->capacity = capacity;
    out->threads = threads;
    out->operations = operations;
    out->lookups = lookups;
    out->stores = stores;
    out->misses = misses;
    out->seconds = (double)(end - start) / 1e9;
    out->evictions = evictions;
    out->expirations = expirations;

    free(tids);
    free(args);
    dns_cache_destroy(&cache);
    return 0;
}

static void print_result(const bench_result_t *r) {
    double ops_per_sec = r->seconds > 0.0 ? (double)r->operations / r->seconds : 0.0;
    double lookup_pct = r->operations > 0 ? ((double)r->lookups * 100.0 / (double)r->operations) : 0.0;
    double store_pct = r->operations > 0 ? ((double)r->stores * 100.0 / (double)r->operations) : 0.0;
    double miss_lookup_pct = r->operations > 0 ? ((double)r->misses * 100.0 / (double)r->operations) : 0.0;

    printf(
        "\n=== capacity=%zu ===\n"
        "workload: ops=%zu time=%.3fs ops/s=%.0f\n"
        "mix: lookups=%zu (%.1f%%), stores=%zu (%.1f%%), miss-lookups=%zu (%.1f%%)\n"
        "cache-state: preload=%zu evictions=%" PRIu64 " expirations=%" PRIu64 " bytes=%zu\n",
        r->capacity,
        r->operations,
        r->seconds,
        ops_per_sec,
        r->lookups,
        lookup_pct,
        r->stores,
        store_pct,
        r->misses,
        miss_lookup_pct,
        r->preload,
        r->evictions,
        r->expirations,
        r->bytes_in_use);
}

static void print_depth_latency_table(size_t capacity, const depth_latency_t *rows, size_t row_count) {
    (void)capacity;
    printf("depth latency (baseline = first row)\n");
    if (row_count == 0) {
        return;
    }

    const double base_avg = rows[0].avg_lookup_us > 0.0 ? rows[0].avg_lookup_us : 1.0;
    const double base_hit = rows[0].avg_hit_lookup_us > 0.0 ? rows[0].avg_hit_lookup_us : 1.0;
    const double base_miss = rows[0].avg_miss_lookup_us > 0.0 ? rows[0].avg_miss_lookup_us : 1.0;

    double worst_x = 1.0;
    double worst_pct = 0.0;
    size_t worst_depth = rows[0].depth_entries;

    printf("  %8s %8s %10s %10s %8s %8s\n", "depth%", "avg(ns)", "slowdown", "delta%", "hit(ns)", "miss(ns)");
    printf("  %8s %8s %10s %10s %8s %8s\n", "------", "-------", "--------", "------", "-------", "--------");

    for (size_t i = 0; i < row_count; i++) {
        const depth_latency_t *row = &rows[i];
        double pct = capacity > 0 ? ((double)row->depth_entries * 100.0 / (double)capacity) : 0.0;
        double avg_x = row->avg_lookup_us / base_avg;
        (void)base_hit;
        (void)base_miss;
        double avg_delta_pct = (avg_x - 1.0) * 100.0;

        if (avg_x > worst_x) {
            worst_x = avg_x;
            worst_pct = avg_delta_pct;
            worst_depth = row->depth_entries;
        }

        char slowdown_buf[32];
        snprintf(slowdown_buf, sizeof(slowdown_buf), "x%.2f", avg_x);

        printf(
            "  %7.1f%% %8.0f %10s %9.1f%% %8.0f %8.0f\n",
            pct,
            row->avg_lookup_us * 1000.0,
            slowdown_buf,
            avg_delta_pct,
            row->avg_hit_lookup_us * 1000.0,
            row->avg_miss_lookup_us * 1000.0);
    }

    printf("  worst depth slowdown: x%.2f (%+.1f%%) at depth=%zu\n", worst_x, worst_pct, worst_depth);
}

static void print_threaded_header(size_t capacity, size_t operations) {
    printf("threaded throughput (capacity=%zu, total-ops=%zu)\n", capacity, operations);
    printf("  %8s %12s %10s %10s %10s\n", "threads", "ops/s", "seconds", "evictions", "expirations");
    printf("  %8s %12s %10s %10s %10s\n", "-------", "-----", "-------", "---------", "-----------");
}

static void print_threaded_row(const threaded_result_t *r, double baseline_ops_per_sec) {
    double ops_per_sec = r->seconds > 0.0 ? (double)r->operations / r->seconds : 0.0;
    double scaling = baseline_ops_per_sec > 0.0 ? ops_per_sec / baseline_ops_per_sec : 1.0;
    printf(
        "  %8zu %12.0f %10.3f %10" PRIu64 " %10" PRIu64 "  (x%.2f vs 1 thread)\n",
        r->threads,
        ops_per_sec,
        r->seconds,
        r->evictions,
        r->expirations,
        scaling);
}

int main(int argc, char **argv) {
    size_t operations = 200000;
    size_t max_threads = 0;
    if (argc > 1) {
        char *end = NULL;
        unsigned long long parsed = strtoull(argv[1], &end, 10);
        if (end != NULL && *end == '\0' && parsed > 0) {
            operations = (size_t)parsed;
        }
    }
    if (argc > 2) {
        char *end = NULL;
        unsigned long long parsed = strtoull(argv[2], &end, 10);
        if (end != NULL && *end == '\0' && parsed > 0) {
            max_threads = (size_t)parsed;
        }
    }
    if (max_threads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) {
            ncpu = 4;
        }
        max_threads = (size_t)ncpu;
        if (max_threads > 8) {
            max_threads = 8;
        }
    }
    if (max_threads < 1) {
        max_threads = 1;
    }

    const size_t capacities[] = {1024, 4096, 16384};
    printf("cache_bench: operations per run=%zu max_threads=%zu\n", operations, max_threads);
    for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); i++) {
        bench_result_t result;
        if (run_bench(capacities[i], operations, &result) != 0) {
            fprintf(stderr, "benchmark failed for capacity=%zu\n", capacities[i]);
            return 1;
        }
        print_result(&result);

        depth_latency_t depths[] = {
            {.depth_entries = capacities[i] / 10},
            {.depth_entries = capacities[i] / 4},
            {.depth_entries = capacities[i] / 2},
            {.depth_entries = (capacities[i] * 3) / 4},
            {.depth_entries = capacities[i]},
        };
        if (run_depth_latency_sweep(capacities[i], depths, sizeof(depths) / sizeof(depths[0])) != 0) {
            fprintf(stderr, "depth latency sweep failed for capacity=%zu\n", capacities[i]);
            return 1;
        }
        print_depth_latency_table(capacities[i], depths, sizeof(depths) / sizeof(depths[0]));

        size_t thread_steps[16];
        size_t step_count = 0;
        for (size_t t = 1; t <= max_threads && step_count < (sizeof(thread_steps) / sizeof(thread_steps[0])); t <<= 1) {
            thread_steps[step_count++] = t;
        }
        if (thread_steps[step_count - 1] != max_threads && step_count < (sizeof(thread_steps) / sizeof(thread_steps[0]))) {
            thread_steps[step_count++] = max_threads;
        }

        print_threaded_header(capacities[i], operations);
        double baseline_ops_per_sec = 0.0;
        for (size_t s = 0; s < step_count; s++) {
            threaded_result_t tr;
            if (run_threaded_bench(capacities[i], operations, thread_steps[s], &tr) != 0) {
                fprintf(stderr, "threaded benchmark failed for capacity=%zu threads=%zu\n", capacities[i], thread_steps[s]);
                return 1;
            }
            if (thread_steps[s] == 1) {
                baseline_ops_per_sec = tr.seconds > 0.0 ? (double)tr.operations / tr.seconds : 0.0;
            }
            print_threaded_row(&tr, baseline_ops_per_sec);
        }
    }

    return 0;
}
