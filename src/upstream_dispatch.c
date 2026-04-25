#define _POSIX_C_SOURCE 200809L

#include "upstream_dispatch.h"

#include "logger.h"
#include "upstream_bootstrap.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FACILITATOR_MAX_MEMBERS 32
#define MEMBER_FAILURE_COOLDOWN_MS 500ULL
#define MEMBER_REFRESH_JITTER_MS 250ULL

static void log_allocator_stage_event(
    const char *caller_func,
    upstream_member_t *member,
    const char *stage,
    const char *action,
    const char *reason,
    const char *detail) {
    logger_logf(
        caller_func,
        "DEBUG",
        "allocator connect event: provider=%d slot=%d stage=%s action=%s reason=%s detail=%s",
        member->provider_index,
        member->slot_index,
        stage != NULL ? stage : "none",
        action != NULL ? action : "none",
        reason != NULL ? reason : "none",
        detail != NULL ? detail : "none");
}

#define LOG_ALLOCATOR_STAGE(member, stage, action, reason, detail) \
    log_allocator_stage_event(__func__, member, stage, action, reason, detail)

static int allocator_connect_member(upstream_facilitator_t *fac, upstream_member_t *member, uint64_t now) {
    upstream_client_t *client = fac->upstream;
    upstream_server_t *server = &client->servers[member->provider_index];

    int timeout_ms = client->config.timeout_ms;
    if (timeout_ms <= 0) {
        timeout_ms = 1000;
    }
    if (timeout_ms > 300) {
        timeout_ms = 300;
    }

    pthread_mutex_lock(&client->stage1_cache_mutex);
    upstream_stage1_cache_result_t stage1 = upstream_bootstrap_stage1_prepare(server);
    pthread_mutex_unlock(&client->stage1_cache_mutex);

    if (stage1 == UPSTREAM_STAGE1_CACHE_HIT || stage1 == UPSTREAM_STAGE1_CACHE_REFRESHED) {
        if (stage1 == UPSTREAM_STAGE1_CACHE_REFRESHED) {
            (void)upstream_bootstrap_stage1_hydrate(client, server, timeout_ms / 2);
        }
        LOG_ALLOCATOR_STAGE(member, "stage1", "success", "local_cache", "stage1_ready");
        return 0;
    }

    const char *stage2_reason = NULL;
    LOG_ALLOCATOR_STAGE(member, "stage1", "failed", "cache_miss", NULL);
    if (upstream_bootstrap_try_stage2(client, server, timeout_ms, &stage2_reason) == 0) {
        LOG_ALLOCATOR_STAGE(member, "stage2", "success", "bootstrap", NULL);
        return 0;
    }
    LOG_ALLOCATOR_STAGE(member, "stage2", "failed", stage2_reason, NULL);

    if (!client->config.iterative_bootstrap_enabled) {
        return -1;
    }

    const char *stage3_reason = NULL;
    if (upstream_bootstrap_try_stage3(server, timeout_ms, &stage3_reason) == 0) {
        LOG_ALLOCATOR_STAGE(member, "stage3", "success", "iterative", NULL);
        return 0;
    }
    LOG_ALLOCATOR_STAGE(member, "stage3", "failed", stage3_reason, NULL);
    (void)now;
    return -1;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void queue_push(upstream_job_t **head, upstream_job_t **tail, upstream_job_t *job) {
    job->next = NULL;
    if (*tail == NULL) {
        *head = job;
        *tail = job;
        return;
    }
    (*tail)->next = job;
    *tail = job;
}

static upstream_job_t *queue_pop(upstream_job_t **head, upstream_job_t **tail) {
    upstream_job_t *job = *head;
    if (job == NULL) {
        return NULL;
    }
    *head = job->next;
    if (*head == NULL) {
        *tail = NULL;
    }
    job->next = NULL;
    return job;
}

static void finalize_job(upstream_job_t *job, int result, uint8_t *response, size_t response_len) {
    pthread_mutex_lock(&job->mutex);
    if (!job->done) {
        job->result = result;
        job->response = response;
        job->response_len = response_len;
        job->done = 1;
        pthread_cond_signal(&job->cond);
    } else {
        free(response);
    }
    pthread_mutex_unlock(&job->mutex);
}

static const char *member_state_name(int state) {
    switch ((upstream_member_state_t)state) {
        case UPSTREAM_MEMBER_UNINIT:
            return "uninit";
        case UPSTREAM_MEMBER_CONNECTING:
            return "connecting";
        case UPSTREAM_MEMBER_READY:
            return "ready";
        case UPSTREAM_MEMBER_ENQUEUED:
            return "enqueued";
        case UPSTREAM_MEMBER_BUSY:
            return "busy";
        case UPSTREAM_MEMBER_FAILED:
            return "failed";
        case UPSTREAM_MEMBER_COOLDOWN:
            return "cooldown";
        case UPSTREAM_MEMBER_DRAINING:
            return "draining";
        default:
            return "unknown";
    }
}

static void member_set_error(upstream_member_t *member, int cls, const char *detail) {
    if (member == NULL) {
        return;
    }
    member->last_error_class = cls;
    if (detail == NULL || *detail == '\0') {
        member->last_error_detail[0] = '\0';
        return;
    }
    strncpy(member->last_error_detail, detail, sizeof(member->last_error_detail) - 1);
    member->last_error_detail[sizeof(member->last_error_detail) - 1] = '\0';
}

static void inflight_add(upstream_facilitator_t *fac, upstream_job_t *job, int member_index) {
    upstream_inflight_entry_t *entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        return;
    }
    entry->job_id = job->job_id;
    entry->member_index = member_index;
    entry->job = job;
    entry->next = fac->inflight_head;
    fac->inflight_head = entry;
}

static upstream_inflight_entry_t *inflight_remove(upstream_facilitator_t *fac, uint64_t job_id) {
    upstream_inflight_entry_t *prev = NULL;
    upstream_inflight_entry_t *cur = fac->inflight_head;
    while (cur != NULL) {
        if (cur->job_id == job_id) {
            if (prev == NULL) {
                fac->inflight_head = cur->next;
            } else {
                prev->next = cur->next;
            }
            cur->next = NULL;
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }
    return NULL;
}

/*
 * Detach an entry's job from the member's assigned queue. Caller must hold
 * the member's mutex. Returns 1 if the job was found and removed, 0 if not
 * (meaning a worker has already popped the job and is processing it).
 */
static int unlink_from_assigned_queue(upstream_member_t *member, upstream_job_t *target) {
    upstream_job_t *prev = NULL;
    upstream_job_t *cur = member->assigned_head;
    while (cur != NULL) {
        if (cur == target) {
            if (prev == NULL) {
                member->assigned_head = cur->next;
            } else {
                prev->next = cur->next;
            }
            if (member->assigned_tail == cur) {
                member->assigned_tail = prev;
            }
            cur->next = NULL;
            return 1;
        }
        prev = cur;
        cur = cur->next;
    }
    return 0;
}

/*
 * Move all inflight entries for this member into a returned drain list, EXCEPT
 * those whose jobs are currently held by a worker thread (i.e. already popped
 * from member->assigned_head). Caller must hold fac->queue_mutex.
 *
 * Worker-held jobs cannot be safely finalized here because the worker still
 * holds the job pointer locally and will write to it after upstream_resolve
 * returns. The worker's natural completion path (push to completed → completion
 * thread inflight_remove) cleans those up. Their inflight entries are left in
 * place; the worker's eventual push to completed will trigger normal handling.
 *
 * For jobs still queued (not yet popped by a worker), we additionally remove
 * them from member->assigned_head so the member's worker thread doesn't try
 * to process a job that has already been finalized.
 */
static upstream_inflight_entry_t *inflight_drain_member(upstream_facilitator_t *fac, int member_index) {
    upstream_inflight_entry_t *drained_head = NULL;
    upstream_inflight_entry_t *drained_tail = NULL;
    upstream_inflight_entry_t *prev = NULL;
    upstream_inflight_entry_t *cur = fac->inflight_head;

    upstream_member_t *member = (member_index >= 0 && member_index < fac->member_count)
        ? &fac->members[member_index]
        : NULL;
    if (member != NULL) {
        pthread_mutex_lock(&member->mutex);
    }

    while (cur != NULL) {
        upstream_inflight_entry_t *next = cur->next;
        int drainable = 0;
        if (cur->member_index == member_index) {
            /* Only drain if the job is still in the assigned queue. If the
             * worker has already popped it, leave the inflight entry in place
             * for the worker's natural completion. */
            if (member != NULL && unlink_from_assigned_queue(member, cur->job)) {
                drainable = 1;
            }
        }
        if (drainable) {
            if (prev == NULL) {
                fac->inflight_head = next;
            } else {
                prev->next = next;
            }
            cur->next = NULL;
            if (drained_tail == NULL) {
                drained_head = cur;
                drained_tail = cur;
            } else {
                drained_tail->next = cur;
                drained_tail = cur;
            }
        } else {
            prev = cur;
        }
        cur = next;
    }

    if (member != NULL) {
        pthread_mutex_unlock(&member->mutex);
    }
    return drained_head;
}

static void member_set_state(
    const char *caller_func,
    upstream_member_t *member,
    int new_state,
    const char *reason) {
    int old_state = atomic_load(&member->state);
    if (old_state == new_state) {
        return;
    }
    atomic_store(&member->state, new_state);
    logger_logf(
        caller_func,
        "DEBUG",
        "dispatch member state: provider=%d slot=%d from=%s to=%s reason=%s",
        member->provider_index,
        member->slot_index,
        member_state_name(old_state),
        member_state_name(new_state),
        reason != NULL ? reason : "none");
}

#define MEMBER_SET_STATE(member, new_state, reason) \
    member_set_state(__func__, member, new_state, reason)

static void record_queue_wait_ms(upstream_facilitator_t *fac, uint64_t wait_ms) {
    atomic_fetch_add(&fac->queue_wait_samples_total, 1);
    atomic_fetch_add(&fac->queue_wait_ms_total, wait_ms);

    uint64_t prev_max = atomic_load(&fac->queue_wait_ms_max);
    while (wait_ms > prev_max && !atomic_compare_exchange_weak(&fac->queue_wait_ms_max, &prev_max, wait_ms)) {
    }

    if (wait_ms <= 1) {
        atomic_fetch_add(&fac->queue_wait_le_1ms, 1);
    } else if (wait_ms <= 5) {
        atomic_fetch_add(&fac->queue_wait_le_5ms, 1);
    } else if (wait_ms <= 10) {
        atomic_fetch_add(&fac->queue_wait_le_10ms, 1);
    } else if (wait_ms <= 25) {
        atomic_fetch_add(&fac->queue_wait_le_25ms, 1);
    } else if (wait_ms <= 50) {
        atomic_fetch_add(&fac->queue_wait_le_50ms, 1);
    } else if (wait_ms <= 100) {
        atomic_fetch_add(&fac->queue_wait_le_100ms, 1);
    } else if (wait_ms <= 250) {
        atomic_fetch_add(&fac->queue_wait_le_250ms, 1);
    } else if (wait_ms <= 500) {
        atomic_fetch_add(&fac->queue_wait_le_500ms, 1);
    } else if (wait_ms <= 1000) {
        atomic_fetch_add(&fac->queue_wait_le_1000ms, 1);
    } else {
        atomic_fetch_add(&fac->queue_wait_gt_1000ms, 1);
    }
}

static int member_is_dispatchable(upstream_member_t *member, uint64_t now) {
    int state = atomic_load(&member->state);
    (void)now;

    if (state != UPSTREAM_MEMBER_READY && state != UPSTREAM_MEMBER_ENQUEUED && state != UPSTREAM_MEMBER_BUSY) {
        return 0;
    }
    if (atomic_load(&member->inflight) >= member->max_inflight) {
        return 0;
    }
    return 1;
}

static uint32_t provider_penalty_score(const upstream_facilitator_t *fac, int provider, uint64_t now);

static void *allocator_thread_main(void *arg) {
    upstream_facilitator_t *fac = (upstream_facilitator_t *)arg;
    while (1) {
        pthread_mutex_lock(&fac->queue_mutex);
        int running = fac->running;
        pthread_mutex_unlock(&fac->queue_mutex);
        if (!running) {
            break;
        }

        uint64_t now = now_ms();
        for (int i = 0; i < fac->member_count; i++) {
            upstream_member_t *member = &fac->members[i];
            upstream_server_t *server = &fac->upstream->servers[member->provider_index];
            int state = atomic_load(&member->state);
            if (state == UPSTREAM_MEMBER_UNINIT) {
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_CONNECTING, "allocator_init");
                member->ttl_expire_ms = 0;
                member->refresh_due_ms = now;
                continue;
            }
            if (state == UPSTREAM_MEMBER_CONNECTING) {
                if (allocator_connect_member(fac, member, now) == 0) {
                    uint64_t ttl_target = now + 5000ULL;
                    if (server->stage.has_stage1_cached_v4 && server->stage.stage1_cache_expires_at_ms > now) {
                        ttl_target = server->stage.stage1_cache_expires_at_ms;
                    } else if (server->stage.has_bootstrap_v4 && server->stage.bootstrap_expires_at_ms > now) {
                        ttl_target = server->stage.bootstrap_expires_at_ms;
                    }
                    member->ttl_expire_ms = ttl_target;
                    member->refresh_due_ms = now + MEMBER_REFRESH_JITTER_MS;
                    member_set_error(member, 0, NULL);
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_READY, "allocator_connect_success");
                } else {
                    member->next_retry_ms = now + MEMBER_FAILURE_COOLDOWN_MS;
                    member_set_error(member, 1, "allocator_connect_failed");
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_FAILED, "allocator_connect_failed");
                }
                continue;
            }
            if (state == UPSTREAM_MEMBER_READY) {
                if (member->ttl_expire_ms != 0 && now >= member->ttl_expire_ms) {
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_CONNECTING, "allocator_ttl_expired");
                    continue;
                }
                if (member->refresh_due_ms != 0 && now >= member->refresh_due_ms) {
                    member->refresh_due_ms = now + MEMBER_REFRESH_JITTER_MS;
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_CONNECTING, "allocator_refresh_due");
                    continue;
                }
            }
            if (state == UPSTREAM_MEMBER_FAILED) {
                if (member->next_retry_ms == 0) {
                    member->next_retry_ms = now + MEMBER_FAILURE_COOLDOWN_MS;
                }
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_COOLDOWN, "allocator_failed_to_cooldown");
                continue;
            }
            if (state == UPSTREAM_MEMBER_COOLDOWN && now >= member->next_retry_ms) {
                member->next_retry_ms = 0;
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_CONNECTING, "allocator_cooldown_expired");
            }
        }

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static int select_member_index(upstream_facilitator_t *fac, uint64_t now) {
    if (fac->member_count <= 0 || fac->provider_count <= 0 || fac->members_per_provider <= 0) {
        return -1;
    }

    int provider_order[UPSTREAM_MAX_SERVERS];
    int provider_used[UPSTREAM_MAX_SERVERS];
    memset(provider_used, 0, sizeof(provider_used));

    for (int rank = 0; rank < fac->provider_count; rank++) {
        int best_provider = -1;
        uint32_t best_score = UINT_MAX;

        for (int provider = 0; provider < fac->provider_count; provider++) {
            if (provider_used[provider]) {
                continue;
            }

            uint32_t score = provider_penalty_score(fac, provider, now);
            if (best_provider < 0 || score < best_score || (score == best_score && provider < best_provider)) {
                best_provider = provider;
                best_score = score;
            }
        }

        if (best_provider < 0) {
            return -1;
        }
        provider_used[best_provider] = 1;
        provider_order[rank] = best_provider;
    }

    for (int rank = 0; rank < fac->provider_count; rank++) {
        int provider = provider_order[rank];
        int start = fac->provider_cursors[provider];
        int best_idx = -1;
        unsigned int best_inflight = UINT_MAX;
        uint64_t best_ttl = 0;
        for (int i = 0; i < fac->members_per_provider; i++) {
            int slot = (start + i) % fac->members_per_provider;
            int idx = provider * fac->members_per_provider + slot;
            if (member_is_dispatchable(&fac->members[idx], now)) {
                unsigned int inflight = atomic_load(&fac->members[idx].inflight);
                uint64_t ttl = fac->members[idx].ttl_expire_ms;
                if (best_idx < 0 || inflight < best_inflight ||
                    (inflight == best_inflight && ttl > best_ttl)) {
                    best_idx = idx;
                    best_inflight = inflight;
                    best_ttl = ttl;
                }
            }
        }
        if (best_idx >= 0) {
            int chosen_slot = best_idx % fac->members_per_provider;
            fac->provider_cursors[provider] = (chosen_slot + 1) % fac->members_per_provider;
            return best_idx;
        }
    }
    return -1;
}

static uint32_t provider_penalty_score(const upstream_facilitator_t *fac, int provider, uint64_t now) {
    upstream_server_t *server = &fac->upstream->servers[provider];
    uint32_t score = 0;

    if (!server->health.healthy) {
        score += 1000;
    }
    score += server->health.consecutive_failures * 100;

    if (server->stage.last_failure_class == UPSTREAM_FAILURE_CLASS_TRANSPORT ||
        server->stage.last_failure_class == UPSTREAM_FAILURE_CLASS_TIMEOUT ||
        server->stage.last_failure_class == UPSTREAM_FAILURE_CLASS_TLS) {
        score += 300;
        if (server->stage.transport_retry_suppress_until_ms > now) {
            score += 700;
        }
    }

    if (server->health.last_failure_time != 0) {
        uint64_t age_ms = now > server->health.last_failure_time ? now - server->health.last_failure_time : 0;
        if (age_ms < 10000) {
            score += 200;
        }
    }

    return score;
}

static void *member_worker_thread_main(void *arg) {
    upstream_member_t *member = (upstream_member_t *)arg;
    if (member == NULL || member->facilitator == NULL) {
        return NULL;
    }
    upstream_facilitator_t *fac = member->facilitator;

    while (1) {
        pthread_mutex_lock(&member->mutex);
        while (member->running && member->assigned_head == NULL) {
            pthread_cond_wait(&member->cond, &member->mutex);
        }
        if (!member->running && member->assigned_head == NULL) {
            pthread_mutex_unlock(&member->mutex);
            break;
        }

        upstream_job_t *job = queue_pop(&member->assigned_head, &member->assigned_tail);
        pthread_mutex_unlock(&member->mutex);
        if (job == NULL) {
            continue;
        }

        MEMBER_SET_STATE(member, UPSTREAM_MEMBER_BUSY, "job_start");

        uint64_t now = now_ms();
        if (job->enqueue_ms != 0 && now >= job->enqueue_ms) {
            record_queue_wait_ms(fac, now - job->enqueue_ms);
        }

        uint8_t *response = NULL;
        size_t response_len = 0;
        int rc = -1;

        now = now_ms();
        if (job->deadline_ms != 0 && now >= job->deadline_ms) {
            rc = -1;
        } else {
            rc = upstream_resolve_on_server_with_deadline(
                fac->upstream,
                member->provider_index,
                job->query,
                job->query_len,
                job->deadline_ms,
                &response,
                &response_len);
            job->attempts++;
        }

        pthread_mutex_lock(&fac->queue_mutex);
        job->result = rc;
        job->response = response;
        job->response_len = response_len;
        queue_push(&fac->completed_head, &fac->completed_tail, job);
        pthread_cond_broadcast(&fac->queue_cond);
        pthread_mutex_unlock(&fac->queue_mutex);
    }

    return NULL;
}

static void *dispatcher_thread_main(void *arg) {
    upstream_facilitator_t *fac = (upstream_facilitator_t *)arg;
    while (1) {
        pthread_mutex_lock(&fac->queue_mutex);
        while (fac->running && fac->submit_head == NULL) {
            pthread_cond_wait(&fac->queue_cond, &fac->queue_mutex);
        }
        if (!fac->running && fac->submit_head == NULL) {
            pthread_mutex_unlock(&fac->queue_mutex);
            break;
        }

        upstream_job_t *job = queue_pop(&fac->submit_head, &fac->submit_tail);
        if (job == NULL) {
            pthread_mutex_unlock(&fac->queue_mutex);
            continue;
        }

        uint64_t now = now_ms();
        if (job->deadline_ms != 0 && now >= job->deadline_ms) {
            atomic_fetch_add(&fac->budget_exhausted_total, 1);
            job->result = -1;
            queue_push(&fac->completed_head, &fac->completed_tail, job);
            pthread_cond_broadcast(&fac->queue_cond);
            pthread_mutex_unlock(&fac->queue_mutex);
            continue;
        }

        int member_idx = select_member_index(fac, now);
        if (member_idx < 0) {
            uint64_t remain_ms = (job->deadline_ms > now) ? (job->deadline_ms - now) : 0;
            if (remain_ms == 0) {
                atomic_fetch_add(&fac->budget_exhausted_total, 1);
                job->result = -1;
                queue_push(&fac->completed_head, &fac->completed_tail, job);
                pthread_cond_broadcast(&fac->queue_cond);
            } else {
                atomic_fetch_add(&fac->requeued_total, 1);
                queue_push(&fac->submit_head, &fac->submit_tail, job);
            }
            pthread_mutex_unlock(&fac->queue_mutex);
            if (remain_ms > 0) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 2 * 1000 * 1000};
                nanosleep(&ts, NULL);
            }
            continue;
        }

        upstream_member_t *member = &fac->members[member_idx];
        atomic_fetch_add(&member->inflight, 1);
        MEMBER_SET_STATE(member, UPSTREAM_MEMBER_ENQUEUED, "job_assigned");

        logger_logf(
            __func__,
            "DEBUG",
            "dispatch assign: job_id=%llu provider=%d slot=%d attempts=%u",
            (unsigned long long)job->job_id,
            member->provider_index,
            member->slot_index,
            (unsigned int)job->attempts);

        pthread_mutex_lock(&member->mutex);
        queue_push(&member->assigned_head, &member->assigned_tail, job);
        job->member_index = member_idx;
        if (job->history_len < UPSTREAM_MAX_SERVERS) {
            job->provider_history[job->history_len] = (uint8_t)member->provider_index;
            job->member_history[job->history_len] = (uint8_t)member->slot_index;
            job->history_len++;
        }
        inflight_add(fac, job, member_idx);
        pthread_cond_signal(&member->cond);
        pthread_mutex_unlock(&member->mutex);

        pthread_mutex_unlock(&fac->queue_mutex);
    }
    return NULL;
}

static void *completion_thread_main(void *arg) {
    upstream_facilitator_t *fac = (upstream_facilitator_t *)arg;
    while (1) {
        pthread_mutex_lock(&fac->queue_mutex);
        while (fac->running && fac->completed_head == NULL) {
            pthread_cond_wait(&fac->queue_cond, &fac->queue_mutex);
        }
        if (!fac->running && fac->completed_head == NULL) {
            pthread_mutex_unlock(&fac->queue_mutex);
            break;
        }

        upstream_job_t *job = queue_pop(&fac->completed_head, &fac->completed_tail);
        if (job == NULL) {
            pthread_mutex_unlock(&fac->queue_mutex);
            continue;
        }

        upstream_inflight_entry_t *entry = inflight_remove(fac, job->job_id);
        (void)entry;

        upstream_inflight_entry_t *drained = NULL;

        int member_idx = job->member_index;
        if (member_idx >= 0 && member_idx < fac->member_count) {
            upstream_member_t *member = &fac->members[member_idx];
            unsigned int inflight = atomic_load(&member->inflight);
            if (inflight > 0) {
                atomic_fetch_sub(&member->inflight, 1);
            }
            unsigned int remaining_inflight = atomic_load(&member->inflight);

            if (job->result == 0) {
                member_set_error(member, 0, NULL);
                if (remaining_inflight == 0) {
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_READY, "job_success");
                } else {
                    MEMBER_SET_STATE(member, UPSTREAM_MEMBER_BUSY, "job_success_pending");
                }
            } else {
                member->next_retry_ms = now_ms() + MEMBER_FAILURE_COOLDOWN_MS;
                member_set_error(member, 1, "transport_or_upstream_failure");
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_FAILED, "job_failed");
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_DRAINING, "drain_inflight_on_failure");

                /* inflight_drain_member walks member->assigned_head under
                 * member->mutex and unlinks each drainable job from it.
                 * Worker-popped jobs are skipped (they're processed naturally). */
                drained = inflight_drain_member(fac, member_idx);
            }
        }
        pthread_mutex_unlock(&fac->queue_mutex);

        while (drained != NULL) {
            upstream_inflight_entry_t *next = drained->next;
            if (drained->job != NULL && drained->job != job) {
                uint64_t now = now_ms();
                upstream_job_t *drained_job = drained->job;
                drained_job->result = -1;
                if (drained_job->deadline_ms <= now) {
                    atomic_fetch_add(&fac->budget_exhausted_total, 1);
                } else {
                    atomic_fetch_add(&fac->dropped_total, 1);
                }
                finalize_job(drained_job, drained_job->result, drained_job->response, drained_job->response_len);
            }
            free(drained);
            drained = next;
        }

        if (job->result != 0) {
            uint64_t now = now_ms();
            if (job->deadline_ms > now && job->attempts < (uint32_t)fac->provider_count) {
                atomic_fetch_add(&fac->requeued_total, 1);
                pthread_mutex_lock(&fac->queue_mutex);
                queue_push(&fac->submit_head, &fac->submit_tail, job);
                pthread_cond_broadcast(&fac->queue_cond);
                pthread_mutex_unlock(&fac->queue_mutex);
                if (entry != NULL) {
                    free(entry);
                }
                if (member_idx >= 0 && member_idx < fac->member_count) {
                    upstream_member_t *member = &fac->members[member_idx];
                    int state = atomic_load(&member->state);
                    if (state == UPSTREAM_MEMBER_DRAINING) {
                        MEMBER_SET_STATE(member, UPSTREAM_MEMBER_FAILED, "drain_complete");
                    }
                }
                continue;
            }
            if (job->deadline_ms <= now) {
                atomic_fetch_add(&fac->budget_exhausted_total, 1);
            } else {
                atomic_fetch_add(&fac->dropped_total, 1);
            }
        }

        finalize_job(job, job->result, job->response, job->response_len);
        if (entry != NULL) {
            free(entry);
        }

        if (member_idx >= 0 && member_idx < fac->member_count) {
            upstream_member_t *member = &fac->members[member_idx];
            int state = atomic_load(&member->state);
            if (state == UPSTREAM_MEMBER_DRAINING) {
                MEMBER_SET_STATE(member, UPSTREAM_MEMBER_FAILED, "drain_complete");
            }
        }
    }
    return NULL;
}

int upstream_facilitator_init(upstream_facilitator_t *facilitator, upstream_client_t *upstream) {
    if (facilitator == NULL || upstream == NULL) {
        return -1;
    }

    memset(facilitator, 0, sizeof(*facilitator));
    facilitator->upstream = upstream;
    facilitator->running = 1;

    facilitator->provider_count = upstream->server_count;
    if (facilitator->provider_count <= 0) {
        return -1;
    }

    int desired_slots = upstream->config.pool_size;
    if (desired_slots <= 0) {
        desired_slots = 1;
    }
    int max_slots_per_provider = FACILITATOR_MAX_MEMBERS / facilitator->provider_count;
    if (max_slots_per_provider < 1) {
        max_slots_per_provider = 1;
    }
    if (desired_slots > max_slots_per_provider) {
        desired_slots = max_slots_per_provider;
    }

    facilitator->members_per_provider = desired_slots;
    facilitator->member_count = facilitator->provider_count * facilitator->members_per_provider;

    facilitator->members = calloc((size_t)facilitator->member_count, sizeof(*facilitator->members));
    if (facilitator->members == NULL) {
        return -1;
    }
    facilitator->provider_cursors = calloc((size_t)facilitator->provider_count, sizeof(*facilitator->provider_cursors));
    if (facilitator->provider_cursors == NULL) {
        free(facilitator->members);
        memset(facilitator, 0, sizeof(*facilitator));
        return -1;
    }

    if (pthread_mutex_init(&facilitator->queue_mutex, NULL) != 0) {
        free(facilitator->provider_cursors);
        free(facilitator->members);
        memset(facilitator, 0, sizeof(*facilitator));
        return -1;
    }
    if (pthread_cond_init(&facilitator->queue_cond, NULL) != 0) {
        pthread_mutex_destroy(&facilitator->queue_mutex);
        free(facilitator->provider_cursors);
        free(facilitator->members);
        memset(facilitator, 0, sizeof(*facilitator));
        return -1;
    }

    for (int i = 0; i < facilitator->member_count; i++) {
        upstream_member_t *member = &facilitator->members[i];
        member->index = i;
        member->provider_index = i / facilitator->members_per_provider;
        member->slot_index = i % facilitator->members_per_provider;
        member->facilitator = facilitator;
        member->running = 1;
        upstream_type_t provider_type = upstream->servers[member->provider_index].type;
        if (provider_type == UPSTREAM_TYPE_DOH) {
            member->max_inflight = (uint32_t)upstream->config.max_inflight_doh;
        } else if (provider_type == UPSTREAM_TYPE_DOT) {
            member->max_inflight = (uint32_t)upstream->config.max_inflight_dot;
        } else {
            member->max_inflight = (uint32_t)upstream->config.max_inflight_doq;
        }
        if (member->max_inflight == 0) {
            member->max_inflight = 1;
        }
        atomic_store(&member->state, UPSTREAM_MEMBER_UNINIT);
        atomic_store(&member->inflight, 0);
        member->ttl_expire_ms = 0;
        member->refresh_due_ms = 0;
        member->last_error_class = 0;
        member->last_error_detail[0] = '\0';
        member->transport_suppress_until_ms = 0;
        if (pthread_mutex_init(&member->mutex, NULL) != 0 ||
            pthread_cond_init(&member->cond, NULL) != 0 ||
            pthread_create(&member->thread, NULL, member_worker_thread_main, member) != 0) {
            facilitator->running = 0;
            for (int j = 0; j <= i; j++) {
                upstream_member_t *m = &facilitator->members[j];
                if (j < i) {
                    pthread_mutex_lock(&m->mutex);
                    m->running = 0;
                    pthread_cond_signal(&m->cond);
                    pthread_mutex_unlock(&m->mutex);
                    pthread_join(m->thread, NULL);
                }
                pthread_cond_destroy(&m->cond);
                pthread_mutex_destroy(&m->mutex);
            }
            pthread_cond_destroy(&facilitator->queue_cond);
            pthread_mutex_destroy(&facilitator->queue_mutex);
            free(facilitator->provider_cursors);
            free(facilitator->members);
            memset(facilitator, 0, sizeof(*facilitator));
            return -1;
        }
    }

    if (pthread_create(&facilitator->allocator_thread, NULL, allocator_thread_main, facilitator) != 0 ||
        pthread_create(&facilitator->dispatcher_thread, NULL, dispatcher_thread_main, facilitator) != 0 ||
        pthread_create(&facilitator->completion_thread, NULL, completion_thread_main, facilitator) != 0) {
        upstream_facilitator_destroy(facilitator);
        return -1;
    }

    LOGF_INFO(
        "Upstream facilitator initialized: providers=%d slots_per_provider=%d total_members=%d",
        facilitator->provider_count,
        facilitator->members_per_provider,
        facilitator->member_count);
    return 0;
}

void upstream_facilitator_destroy(upstream_facilitator_t *facilitator) {
    if (facilitator == NULL) {
        return;
    }

    pthread_mutex_lock(&facilitator->queue_mutex);
    facilitator->running = 0;
    pthread_cond_broadcast(&facilitator->queue_cond);
    pthread_mutex_unlock(&facilitator->queue_mutex);

    for (int i = 0; i < facilitator->member_count; i++) {
        upstream_member_t *member = &facilitator->members[i];
        pthread_mutex_lock(&member->mutex);
        member->running = 0;
        pthread_cond_signal(&member->cond);
        pthread_mutex_unlock(&member->mutex);
    }

    if (facilitator->dispatcher_thread != 0) {
        pthread_join(facilitator->dispatcher_thread, NULL);
    }
    if (facilitator->completion_thread != 0) {
        pthread_join(facilitator->completion_thread, NULL);
    }
    if (facilitator->allocator_thread != 0) {
        pthread_join(facilitator->allocator_thread, NULL);
    }

    for (int i = 0; i < facilitator->member_count; i++) {
        upstream_member_t *member = &facilitator->members[i];
        if (member->thread != 0) {
            pthread_join(member->thread, NULL);
        }
        pthread_cond_destroy(&member->cond);
        pthread_mutex_destroy(&member->mutex);
    }

    pthread_mutex_lock(&facilitator->queue_mutex);
    upstream_job_t *job = NULL;
    while ((job = queue_pop(&facilitator->submit_head, &facilitator->submit_tail)) != NULL) {
        pthread_mutex_unlock(&facilitator->queue_mutex);
        finalize_job(job, -1, NULL, 0);
        pthread_mutex_lock(&facilitator->queue_mutex);
    }
    while ((job = queue_pop(&facilitator->completed_head, &facilitator->completed_tail)) != NULL) {
        pthread_mutex_unlock(&facilitator->queue_mutex);
        finalize_job(job, job->result, job->response, job->response_len);
        pthread_mutex_lock(&facilitator->queue_mutex);
    }
    while ((job = queue_pop(&facilitator->work_head, &facilitator->work_tail)) != NULL) {
        pthread_mutex_unlock(&facilitator->queue_mutex);
        finalize_job(job, -1, NULL, 0);
        pthread_mutex_lock(&facilitator->queue_mutex);
    }
    while (facilitator->inflight_head != NULL) {
        upstream_inflight_entry_t *next = facilitator->inflight_head->next;
        free(facilitator->inflight_head);
        facilitator->inflight_head = next;
    }
    pthread_mutex_unlock(&facilitator->queue_mutex);

    pthread_cond_destroy(&facilitator->queue_cond);
    pthread_mutex_destroy(&facilitator->queue_mutex);
    free(facilitator->provider_cursors);
    free(facilitator->members);
    memset(facilitator, 0, sizeof(*facilitator));
}

static int resolve_with_job_deadline(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (facilitator == NULL || query == NULL || query_len == 0 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    upstream_job_t *job = calloc(1, sizeof(*job));
    if (job == NULL) {
        return -1;
    }

    job->query = malloc(query_len);
    if (job->query == NULL) {
        free(job);
        return -1;
    }
    memcpy(job->query, query, query_len);
    job->query_len = query_len;
    job->enqueue_ms = now_ms();
    if (deadline_ms != 0) {
        job->deadline_ms = deadline_ms;
    } else {
        int budget_ms = facilitator->upstream->config.timeout_ms;
        if (budget_ms <= 0) {
            budget_ms = 1000;
        }
        job->deadline_ms = job->enqueue_ms + (uint64_t)budget_ms;
    }
    job->member_index = -1;

    if (pthread_mutex_init(&job->mutex, NULL) != 0) {
        free(job->query);
        free(job);
        return -1;
    }
    if (pthread_cond_init(&job->cond, NULL) != 0) {
        pthread_mutex_destroy(&job->mutex);
        free(job->query);
        free(job);
        return -1;
    }

    pthread_mutex_lock(&facilitator->queue_mutex);
    if (!facilitator->running) {
        pthread_mutex_unlock(&facilitator->queue_mutex);
        pthread_cond_destroy(&job->cond);
        pthread_mutex_destroy(&job->mutex);
        free(job->query);
        free(job);
        return -1;
    }
    job->job_id = ++facilitator->next_job_id;
    queue_push(&facilitator->submit_head, &facilitator->submit_tail, job);
    pthread_cond_broadcast(&facilitator->queue_cond);
    pthread_mutex_unlock(&facilitator->queue_mutex);

    pthread_mutex_lock(&job->mutex);
    while (!job->done) {
        pthread_cond_wait(&job->cond, &job->mutex);
    }
    pthread_mutex_unlock(&job->mutex);

    int rc = job->result;
    if (rc == 0) {
        *response_out = job->response;
        *response_len_out = job->response_len;
    } else {
        free(job->response);
    }

    free(job->query);
    pthread_cond_destroy(&job->cond);
    pthread_mutex_destroy(&job->mutex);
    free(job);
    return rc;
}

int upstream_facilitator_resolve_with_deadline(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out) {
    return resolve_with_job_deadline(facilitator, query, query_len, deadline_ms, response_out, response_len_out);
}

int upstream_facilitator_resolve(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    return resolve_with_job_deadline(facilitator, query, query_len, 0, response_out, response_len_out);
}

int upstream_facilitator_get_stats(
    upstream_facilitator_t *facilitator,
    upstream_facilitator_stats_t *stats_out) {
    if (facilitator == NULL || stats_out == NULL) {
        return -1;
    }

    memset(stats_out, 0, sizeof(*stats_out));
    stats_out->member_count = facilitator->member_count;
    stats_out->budget_exhausted_total = (uint64_t)atomic_load(&facilitator->budget_exhausted_total);
    stats_out->requeued_total = (uint64_t)atomic_load(&facilitator->requeued_total);
    stats_out->dropped_total = (uint64_t)atomic_load(&facilitator->dropped_total);
    stats_out->queue_wait_samples_total = (uint64_t)atomic_load(&facilitator->queue_wait_samples_total);
    stats_out->queue_wait_ms_total = (uint64_t)atomic_load(&facilitator->queue_wait_ms_total);
    stats_out->queue_wait_ms_max = (uint64_t)atomic_load(&facilitator->queue_wait_ms_max);
    stats_out->queue_wait_le_1ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_1ms);
    stats_out->queue_wait_le_5ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_5ms);
    stats_out->queue_wait_le_10ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_10ms);
    stats_out->queue_wait_le_25ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_25ms);
    stats_out->queue_wait_le_50ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_50ms);
    stats_out->queue_wait_le_100ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_100ms);
    stats_out->queue_wait_le_250ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_250ms);
    stats_out->queue_wait_le_500ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_500ms);
    stats_out->queue_wait_le_1000ms = (uint64_t)atomic_load(&facilitator->queue_wait_le_1000ms);
    stats_out->queue_wait_gt_1000ms = (uint64_t)atomic_load(&facilitator->queue_wait_gt_1000ms);

    pthread_mutex_lock(&facilitator->queue_mutex);
    for (upstream_job_t *j = facilitator->submit_head; j != NULL; j = j->next) {
        stats_out->submit_queue_depth++;
    }
    for (upstream_job_t *j = facilitator->work_head; j != NULL; j = j->next) {
        stats_out->work_queue_depth++;
    }
    for (upstream_job_t *j = facilitator->completed_head; j != NULL; j = j->next) {
        stats_out->completed_queue_depth++;
    }
    pthread_mutex_unlock(&facilitator->queue_mutex);

    for (int i = 0; i < facilitator->member_count; i++) {
        int state = atomic_load(&facilitator->members[i].state);
        if (state == UPSTREAM_MEMBER_CONNECTING) {
            stats_out->members_connecting++;
        } else if (state == UPSTREAM_MEMBER_READY) {
            stats_out->members_ready++;
        } else if (state == UPSTREAM_MEMBER_ENQUEUED) {
            stats_out->members_enqueued++;
        } else if (state == UPSTREAM_MEMBER_BUSY) {
            stats_out->members_busy++;
        } else if (state == UPSTREAM_MEMBER_COOLDOWN) {
            stats_out->members_cooldown++;
        } else if (state == UPSTREAM_MEMBER_FAILED) {
            stats_out->members_failed++;
        } else if (state == UPSTREAM_MEMBER_DRAINING) {
            stats_out->members_draining++;
        }
    }

    return 0;
}

uint64_t upstream_facilitator_get_provider_inflight(
    const upstream_facilitator_t *facilitator,
    int provider_index) {
    if (facilitator == NULL || provider_index < 0) {
        return 0;
    }

    uint64_t total = 0;
    for (int i = 0; i < facilitator->member_count; i++) {
        const upstream_member_t *member = &facilitator->members[i];
        if (member->provider_index == provider_index) {
            total += (uint64_t)atomic_load(&member->inflight);
        }
    }
    return total;
}

uint64_t upstream_facilitator_get_provider_penalty(
    const upstream_facilitator_t *facilitator,
    int provider_index) {
    if (facilitator == NULL || facilitator->upstream == NULL ||
        provider_index < 0 || provider_index >= facilitator->provider_count) {
        return 0;
    }

    uint64_t now = now_ms();
    return (uint64_t)provider_penalty_score(facilitator, provider_index, now);
}
