/*
 * Unit tests for the project-wide error infrastructure (src/errors.c).
 *
 * Verifies:
 *   - set_error / set_error_errno round-trip into proxy_error_message()
 *   - errno snapshot at the call site survives subsequent errno clobber
 *   - oversized payloads truncate without overflow
 *   - clear() empties the buffer
 *   - thread-local buffer is isolated per thread
 *   - status_name covers every enum value
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "errors.h"

static int setup_clear(void **state) {
    (void)state;
    proxy_error_clear();
    return 0;
}

/*
 * set_error captures the format string and __func__ prefix.
 */
static void test_set_error_round_trip(void **state) {
    (void)state;

    proxy_status_t rc = set_error(PROXY_ERR_CONFIG, "missing key %s", "listen_port");

    assert_int_equal(rc, PROXY_ERR_CONFIG);
    const char *msg = proxy_error_message();
    assert_non_null(msg);
    assert_non_null(strstr(msg, "missing key listen_port"));
    /* __func__ prefix */
    assert_non_null(strstr(msg, "test_set_error_round_trip"));
}

/*
 * set_error_errno appends ": <strerror>" and survives an errno overwrite
 * after the macro expands. EINVAL is portable across glibc/musl.
 */
static void test_set_error_errno_snapshots_errno(void **state) {
    (void)state;

    errno = EINVAL;
    proxy_status_t rc = set_error_errno(PROXY_ERR_NETWORK, "connect to %s", "1.2.3.4");
    /* Clobber errno after the call: the message must already hold the snapshot. */
    errno = 0;

    assert_int_equal(rc, PROXY_ERR_NETWORK);
    const char *msg = proxy_error_message();
    assert_non_null(strstr(msg, "connect to 1.2.3.4"));
    /* The message contains a strerror suffix or "errno=22" fallback. */
    assert_true(strstr(msg, ": ") != NULL);
}

/*
 * Oversized payloads must not overflow the 256-byte thread-local buffer.
 * vsnprintf truncates and we just verify message length is bounded and
 * NUL-terminated.
 */
static void test_payload_truncates(void **state) {
    (void)state;

    char huge[1024];
    memset(huge, 'A', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';

    set_error(PROXY_ERR_INTERNAL, "%s", huge);

    const char *msg = proxy_error_message();
    size_t len = strlen(msg);
    assert_true(len > 0);
    assert_true(len < 256);
}

/*
 * clear() empties the buffer; subsequent reads see "".
 */
static void test_clear_empties_buffer(void **state) {
    (void)state;

    set_error(PROXY_ERR_TIMEOUT, "deadline exceeded");
    assert_true(strlen(proxy_error_message()) > 0);

    proxy_error_clear();
    assert_string_equal(proxy_error_message(), "");
}

/*
 * Worker thread sets a sentinel and reads it back; the main thread's
 * pre-set message must remain untouched. This proves the buffer is
 * thread-local, not global.
 */
static void *thread_worker_set(void *arg) {
    const char *expected_marker = (const char *)arg;
    /* On entry the worker's TLS buffer should be empty (zero-initialized). */
    if (strlen(proxy_error_message()) != 0) {
        return (void *)1;
    }
    set_error(PROXY_ERR_RESOURCE, "%s", expected_marker);
    if (strstr(proxy_error_message(), expected_marker) == NULL) {
        return (void *)2;
    }
    return NULL;
}

static void test_thread_local_isolation(void **state) {
    (void)state;

    set_error(PROXY_ERR_CONFIG, "main-thread-marker");
    const char *main_before = proxy_error_message();
    assert_non_null(strstr(main_before, "main-thread-marker"));

    pthread_t tid;
    char worker_marker[] = "worker-thread-marker";
    int rc = pthread_create(&tid, NULL, thread_worker_set, worker_marker);
    assert_int_equal(rc, 0);

    void *retval = NULL;
    pthread_join(tid, &retval);
    assert_null(retval);

    /* Main thread's message must be unaffected by the worker's set_error(). */
    const char *main_after = proxy_error_message();
    assert_non_null(strstr(main_after, "main-thread-marker"));
    assert_null(strstr(main_after, "worker-thread-marker"));
}

/*
 * Every enum value resolves to a non-NULL, recognizable name. An
 * out-of-range cast falls back to PROXY_ERR_UNKNOWN.
 */
static void test_status_name_coverage(void **state) {
    (void)state;

    assert_string_equal(proxy_status_name(PROXY_OK),              "PROXY_OK");
    assert_string_equal(proxy_status_name(PROXY_ERR_INVALID_ARG), "PROXY_ERR_INVALID_ARG");
    assert_string_equal(proxy_status_name(PROXY_ERR_CONFIG),      "PROXY_ERR_CONFIG");
    assert_string_equal(proxy_status_name(PROXY_ERR_NETWORK),     "PROXY_ERR_NETWORK");
    assert_string_equal(proxy_status_name(PROXY_ERR_PROTOCOL),    "PROXY_ERR_PROTOCOL");
    assert_string_equal(proxy_status_name(PROXY_ERR_TIMEOUT),     "PROXY_ERR_TIMEOUT");
    assert_string_equal(proxy_status_name(PROXY_ERR_RESOURCE),    "PROXY_ERR_RESOURCE");
    assert_string_equal(proxy_status_name(PROXY_ERR_INTERNAL),    "PROXY_ERR_INTERNAL");

    /* Unknown value: cast a sentinel that's not in the enum. */
    assert_string_equal(proxy_status_name((proxy_status_t)-99), "PROXY_ERR_UNKNOWN");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_set_error_round_trip,        setup_clear),
        cmocka_unit_test_setup(test_set_error_errno_snapshots_errno, setup_clear),
        cmocka_unit_test_setup(test_payload_truncates,           setup_clear),
        cmocka_unit_test_setup(test_clear_empties_buffer,        setup_clear),
        cmocka_unit_test_setup(test_thread_local_isolation,      setup_clear),
        cmocka_unit_test_setup(test_status_name_coverage,        setup_clear),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
