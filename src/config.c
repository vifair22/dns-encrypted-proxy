#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void trim_in_place(char *s) {
    char *start = s;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }

    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

static int parse_int(const char *value, int *out) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    if (parsed < 0 || parsed > 65535) {
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

static void split_upstreams(proxy_config_t *config, const char *value) {
    char buffer[MAX_UPSTREAMS * MAX_URL_LEN];
    strncpy(buffer, value, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    config->upstream_count = 0;
    char *token = strtok(buffer, ",");
    while (token != NULL && config->upstream_count < MAX_UPSTREAMS) {
        trim_in_place(token);
        if (*token != '\0') {
            strncpy(config->upstream_urls[config->upstream_count], token, MAX_URL_LEN - 1);
            config->upstream_urls[config->upstream_count][MAX_URL_LEN - 1] = '\0';
            config->upstream_count++;
        }
        token = strtok(NULL, ",");
    }
}

static void apply_key_value(proxy_config_t *config, const char *key, const char *value) {
    if (strcmp(key, "listen_addr") == 0) {
        strncpy(config->listen_addr, value, sizeof(config->listen_addr) - 1);
        config->listen_addr[sizeof(config->listen_addr) - 1] = '\0';
        return;
    }

    if (strcmp(key, "listen_port") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->listen_port = parsed;
        }
        return;
    }

    if (strcmp(key, "upstream_timeout_ms") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->upstream_timeout_ms = parsed;
        }
        return;
    }

    if (strcmp(key, "doh_pool_size") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->doh_pool_size = parsed;
        }
        return;
    }

    if (strcmp(key, "cache_capacity") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->cache_capacity = parsed;
        }
        return;
    }

    if (strcmp(key, "upstream_doh_urls") == 0) {
        split_upstreams(config, value);
        return;
    }

    if (strcmp(key, "tcp_idle_timeout_ms") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->tcp_idle_timeout_ms = parsed;
        }
        return;
    }

    if (strcmp(key, "tcp_max_clients") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->tcp_max_clients = parsed;
        }
        return;
    }

    if (strcmp(key, "tcp_max_queries_per_conn") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->tcp_max_queries_per_conn = parsed;
        }
        return;
    }

    if (strcmp(key, "metrics_port") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->metrics_port = parsed;
        }
        return;
    }

    if (strcmp(key, "metrics_enabled") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->metrics_enabled = parsed ? 1 : 0;
        }
    }
}

static void apply_env_overrides(proxy_config_t *config) {
    const char *value = getenv("LISTEN_ADDR");
    if (value != NULL && *value != '\0') {
        strncpy(config->listen_addr, value, sizeof(config->listen_addr) - 1);
        config->listen_addr[sizeof(config->listen_addr) - 1] = '\0';
    }

    value = getenv("LISTEN_PORT");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->listen_port = parsed;
        }
    }

    value = getenv("UPSTREAM_TIMEOUT_MS");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->upstream_timeout_ms = parsed;
        }
    }

    value = getenv("DOH_POOL_SIZE");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->doh_pool_size = parsed;
        }
    }

    value = getenv("CACHE_CAPACITY");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->cache_capacity = parsed;
        }
    }

    value = getenv("UPSTREAM_DOH_URLS");
    if (value != NULL && *value != '\0') {
        split_upstreams(config, value);
    }

    value = getenv("TCP_IDLE_TIMEOUT_MS");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->tcp_idle_timeout_ms = parsed;
        }
    }

    value = getenv("TCP_MAX_CLIENTS");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->tcp_max_clients = parsed;
        }
    }

    value = getenv("TCP_MAX_QUERIES_PER_CONN");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->tcp_max_queries_per_conn = parsed;
        }
    }

    value = getenv("METRICS_PORT");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed >= 0) {
            config->metrics_port = parsed;
        }
    }

    value = getenv("METRICS_ENABLED");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0) {
            config->metrics_enabled = parsed ? 1 : 0;
        }
    }
}

static void set_defaults(proxy_config_t *config) {
    memset(config, 0, sizeof(*config));
    strncpy(config->listen_addr, "0.0.0.0", sizeof(config->listen_addr) - 1);
    config->listen_port = 53;
    config->upstream_timeout_ms = 2500;
    config->doh_pool_size = 6;
    config->cache_capacity = 1024;

    strncpy(config->upstream_urls[0], "https://cloudflare-dns.com/dns-query", MAX_URL_LEN - 1);
    strncpy(config->upstream_urls[1], "https://dns.google/dns-query", MAX_URL_LEN - 1);
    config->upstream_count = 2;

    strncpy(config->config_path, "doh-proxy.conf", sizeof(config->config_path) - 1);

    config->tcp_idle_timeout_ms = 10000;
    config->tcp_max_clients = 256;
    config->tcp_max_queries_per_conn = 0;
    config->metrics_enabled = 1;
    config->metrics_port = 9090;
}

static void load_config_file(proxy_config_t *config, const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }

    char line[2048];
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_in_place(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            continue;
        }

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        trim_in_place(key);
        trim_in_place(value);

        if (*key == '\0' || *value == '\0') {
            continue;
        }

        apply_key_value(config, key, value);
    }

    fclose(fp);
}

int config_load(proxy_config_t *config, const char *explicit_path) {
    if (config == NULL) {
        return -1;
    }

    set_defaults(config);

    const char *path = explicit_path;
    if (path == NULL || *path == '\0') {
        const char *env_path = getenv("DOH_PROXY_CONFIG");
        if (env_path != NULL && *env_path != '\0') {
            path = env_path;
        } else {
            path = config->config_path;
        }
    }

    strncpy(config->config_path, path, sizeof(config->config_path) - 1);
    config->config_path[sizeof(config->config_path) - 1] = '\0';

    load_config_file(config, config->config_path);
    apply_env_overrides(config);

    if (config->upstream_count <= 0) {
        return -1;
    }

    if (config->listen_port <= 0 || config->listen_port > 65535) {
        return -1;
    }

    if (config->upstream_timeout_ms <= 0) {
        return -1;
    }

    if (config->doh_pool_size <= 0) {
        return -1;
    }

    if (config->cache_capacity <= 0) {
        return -1;
    }

    if (config->metrics_port <= 0 || config->metrics_port > 65535) {
        return -1;
    }

    if (config->metrics_enabled != 0 && config->metrics_enabled != 1) {
        return -1;
    }

    return 0;
}

void config_print(const proxy_config_t *config, FILE *out) {
    if (config == NULL || out == NULL) {
        return;
    }

    fprintf(out, "Configuration:\n");
    fprintf(out, "  listen_addr=%s\n", config->listen_addr);
    fprintf(out, "  listen_port=%d\n", config->listen_port);
    fprintf(out, "  upstream_timeout_ms=%d\n", config->upstream_timeout_ms);
    fprintf(out, "  doh_pool_size=%d\n", config->doh_pool_size);
    fprintf(out, "  cache_capacity=%d\n", config->cache_capacity);
    fprintf(out, "  tcp_idle_timeout_ms=%d\n", config->tcp_idle_timeout_ms);
    fprintf(out, "  tcp_max_clients=%d\n", config->tcp_max_clients);
    fprintf(out, "  tcp_max_queries_per_conn=%d\n", config->tcp_max_queries_per_conn);
    fprintf(out, "  metrics_enabled=%d\n", config->metrics_enabled);
    fprintf(out, "  metrics_port=%d\n", config->metrics_port);
    fprintf(out, "  upstream_doh_urls=");
    for (int i = 0; i < config->upstream_count; i++) {
        fprintf(out, "%s%s", config->upstream_urls[i], (i + 1 == config->upstream_count) ? "" : ",");
    }
    fprintf(out, "\n");
}
