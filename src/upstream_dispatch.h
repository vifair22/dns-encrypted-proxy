#ifndef UPSTREAM_DISPATCH_H
#define UPSTREAM_DISPATCH_H

#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>

#include "upstream.h"

typedef struct upstream_job {
    uint64_t job_id;
    uint8_t *query;
    size_t query_len;
    uint64_t enqueue_ms;
    uint64_t deadline_ms;
    uint32_t attempts;
    int member_index;
    uint8_t provider_history[UPSTREAM_MAX_SERVERS];
    uint8_t member_history[UPSTREAM_MAX_SERVERS];
    uint8_t history_len;
    void *completion_ctx;

    uint8_t *response;
    size_t response_len;
    int result;
    int done;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    struct upstream_job *next;
} upstream_job_t;

struct upstream_facilitator;

typedef enum {
    UPSTREAM_MEMBER_UNINIT = 0,
    UPSTREAM_MEMBER_CONNECTING = 1,
    UPSTREAM_MEMBER_READY = 2,
    UPSTREAM_MEMBER_ENQUEUED = 3,
    UPSTREAM_MEMBER_BUSY = 4,
    UPSTREAM_MEMBER_FAILED = 5,
    UPSTREAM_MEMBER_COOLDOWN = 6,
    UPSTREAM_MEMBER_DRAINING = 7,
} upstream_member_state_t;

typedef struct upstream_inflight_entry {
    uint64_t job_id;
    int member_index;
    upstream_job_t *job;
    struct upstream_inflight_entry *next;
} upstream_inflight_entry_t;

typedef struct {
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct upstream_facilitator *facilitator;

    upstream_job_t *assigned_head;
    upstream_job_t *assigned_tail;

    atomic_int state;
    atomic_uint inflight;
    uint32_t max_inflight;
    uint64_t next_retry_ms;
    uint64_t ttl_expire_ms;
    uint64_t refresh_due_ms;
    int last_error_class;
    char last_error_detail[64];
    uint64_t transport_suppress_until_ms;
    int running;
    int index;
    int provider_index;
    int slot_index;
} upstream_member_t;

typedef struct upstream_facilitator {
    upstream_client_t *upstream;

    pthread_t dispatcher_thread;
    pthread_t completion_thread;
    pthread_t allocator_thread;
    upstream_member_t *members;
    int member_count;
    int provider_count;
    int members_per_provider;

    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    upstream_job_t *submit_head;
    upstream_job_t *submit_tail;
    upstream_job_t *work_head;
    upstream_job_t *work_tail;
    upstream_job_t *completed_head;
    upstream_job_t *completed_tail;
    upstream_inflight_entry_t *inflight_head;

    int *provider_cursors;

    uint64_t next_job_id;
    int running;

    atomic_uint_fast64_t budget_exhausted_total;
    atomic_uint_fast64_t requeued_total;
    atomic_uint_fast64_t dropped_total;

    atomic_uint_fast64_t queue_wait_samples_total;
    atomic_uint_fast64_t queue_wait_ms_total;
    atomic_uint_fast64_t queue_wait_ms_max;
    atomic_uint_fast64_t queue_wait_le_1ms;
    atomic_uint_fast64_t queue_wait_le_5ms;
    atomic_uint_fast64_t queue_wait_le_10ms;
    atomic_uint_fast64_t queue_wait_le_25ms;
    atomic_uint_fast64_t queue_wait_le_50ms;
    atomic_uint_fast64_t queue_wait_le_100ms;
    atomic_uint_fast64_t queue_wait_le_250ms;
    atomic_uint_fast64_t queue_wait_le_500ms;
    atomic_uint_fast64_t queue_wait_le_1000ms;
    atomic_uint_fast64_t queue_wait_gt_1000ms;
} upstream_facilitator_t;

typedef struct {
    uint64_t submit_queue_depth;
    uint64_t work_queue_depth;
    uint64_t completed_queue_depth;
    int member_count;
    uint64_t members_ready;
    uint64_t members_connecting;
    uint64_t members_enqueued;
    uint64_t members_busy;
    uint64_t members_cooldown;
    uint64_t members_failed;
    uint64_t members_draining;
    uint64_t budget_exhausted_total;
    uint64_t requeued_total;
    uint64_t dropped_total;
    uint64_t queue_wait_samples_total;
    uint64_t queue_wait_ms_total;
    uint64_t queue_wait_ms_max;
    uint64_t queue_wait_le_1ms;
    uint64_t queue_wait_le_5ms;
    uint64_t queue_wait_le_10ms;
    uint64_t queue_wait_le_25ms;
    uint64_t queue_wait_le_50ms;
    uint64_t queue_wait_le_100ms;
    uint64_t queue_wait_le_250ms;
    uint64_t queue_wait_le_500ms;
    uint64_t queue_wait_le_1000ms;
    uint64_t queue_wait_gt_1000ms;
} upstream_facilitator_stats_t;

int upstream_facilitator_init(upstream_facilitator_t *facilitator, upstream_client_t *upstream);
void upstream_facilitator_destroy(upstream_facilitator_t *facilitator);
int upstream_facilitator_resolve(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_facilitator_resolve_with_deadline(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_facilitator_get_stats(
    upstream_facilitator_t *facilitator,
    upstream_facilitator_stats_t *stats_out);
uint64_t upstream_facilitator_get_provider_inflight(
    const upstream_facilitator_t *facilitator,
    int provider_index);
uint64_t upstream_facilitator_get_provider_penalty(
    const upstream_facilitator_t *facilitator,
    int provider_index);

#endif
