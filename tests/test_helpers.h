#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

/* Enable POSIX extensions for mkstemp, strdup, setenv, unsetenv */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Common test helper utilities
 */

/* Create a temporary file with given content, returns path (must be freed) */
static inline char *create_temp_file(const char *content) {
    char template[] = "/tmp/dns_encrypted_proxy_test_XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) {
        return NULL;
    }
    
    if (content != NULL) {
        size_t len = strlen(content);
        ssize_t written = write(fd, content, len);
        if (written < 0 || (size_t)written != len) {
            close(fd);
            unlink(template);
            return NULL;
        }
    }
    
    close(fd);
    return strdup(template);
}

/* Remove a temporary file */
static inline void remove_temp_file(char *path) {
    if (path != NULL) {
        unlink(path);
        free(path);
    }
}

/* Helper to clear environment variables used by config */
static inline void clear_config_env_vars(void) {
    unsetenv("LISTEN_ADDR");
    unsetenv("LISTEN_PORT");
    unsetenv("UPSTREAM_TIMEOUT_MS");
    unsetenv("UPSTREAM_POOL_SIZE");
    unsetenv("CACHE_CAPACITY");
    unsetenv("UPSTREAMS");
    unsetenv("TCP_IDLE_TIMEOUT_MS");
    unsetenv("TCP_MAX_CLIENTS");
    unsetenv("TCP_MAX_QUERIES_PER_CONN");
    unsetenv("METRICS_PORT");
    unsetenv("METRICS_ENABLED");
    unsetenv("LOG_LEVEL");
    unsetenv("HOSTS_A");
    unsetenv("BOOTSTRAP_RESOLVERS");
    unsetenv("DNS_ENCRYPTED_PROXY_CONFIG");
}

/* Assert two byte arrays are equal */
static inline void assert_bytes_equal(const uint8_t *expected, const uint8_t *actual, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (expected[i] != actual[i]) {
            fail_msg("Byte mismatch at offset %zu: expected 0x%02x, got 0x%02x",
                     i, expected[i], actual[i]);
        }
    }
}

/* Print bytes in hex for debugging */
static inline void print_bytes(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", data[i]);
    }
    fprintf(stderr, "\n");
}

#endif /* TEST_HELPERS_H */
