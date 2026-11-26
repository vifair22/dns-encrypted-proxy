#ifndef REPORT_H
#define REPORT_H

#include <stddef.h>
#include <stdint.h>

#include "errors.h"

/*
 * Structured event reports for a local collector.
 *
 * Each event is one JSON object in one AF_UNIX datagram, sent without
 * blocking to the path set by `report_socket`. An event that cannot be sent
 * because the collector is absent, slow or full is dropped and counted. The
 * proxy never waits on the collector.
 *
 * The sink is process-wide, because upstream events are raised deep inside
 * the transports, far from anything that could carry a handle. Before
 * report_open, and after report_close, every call is a no-op.
 */

/* Largest datagram the collector accepts. An event that does not fit is
 * dropped rather than truncated, since a cut-off object is not valid JSON. */
#define REPORT_MAX_DATAGRAM 4096

/* Sent as "v" on every record. Bump it only for a change an existing
 * collector would misread, such as a field changing meaning or type; new
 * fields and events keep the version. */
#define REPORT_RECORD_VERSION 1

typedef enum {
    REPORT_SOURCE_UPSTREAM = 0,
    REPORT_SOURCE_CACHE,
    REPORT_SOURCE_FAILURE_CACHE,
    REPORT_SOURCE_LOCAL,
} report_source_t;

typedef struct {
    const char *client;    /* text address; NULL is written as null */
    const char *qname;     /* NULL when the question could not be parsed */
    uint16_t qtype;
    int has_qtype;
    uint8_t rcode;
    report_source_t source;
    const char *upstream;  /* NULL unless source is upstream */
    const char *proto;     /* NULL unless source is upstream */
    double latency_ms;
} report_query_t;

proxy_status_t report_open(const char *path);
void report_close(void);
int report_enabled(void);

void report_query(const report_query_t *query);
/* event: failure, retry, redial, failover, unhealthy or recovered. reason and
 * detail may be NULL. */
void report_upstream(const char *upstream, const char *event, const char *reason, const char *detail);

/* Transports note why their last attempt failed; the health bookkeeping that
 * runs afterwards on the same thread picks the note up for its failure event.
 * A per-thread note avoids threading the detail through every return path. */
void report_note_attempt_failure(const char *reason, const char *detail);
/* Copies the note out (empty strings when there is none) and clears it. */
void report_take_attempt_failure(char *reason, size_t reason_len, char *detail, size_t detail_len);

uint64_t report_sent_total(void);
uint64_t report_dropped_total(void);

/* Encoders, exposed for tests. Return the length written, or -1 when the
 * event does not fit in capacity. ts is seconds since the epoch. */
int report_format_query(char *buf, size_t capacity, double ts, const report_query_t *query);
int report_format_upstream(
    char *buf,
    size_t capacity,
    double ts,
    const char *upstream,
    const char *event,
    const char *reason,
    const char *detail);

const char *report_qtype_name(uint16_t qtype, char *scratch, size_t scratch_len);
const char *report_rcode_name(uint8_t rcode, char *scratch, size_t scratch_len);

#endif
