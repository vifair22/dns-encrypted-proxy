#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void trim_in_place(char *s);

static uint32_t hosts_name_hash(const char *name) {
    uint32_t hash = 2166136261u;
    if (name == NULL) {
        return hash;
    }
    while (*name != '\0') {
        unsigned char ch = (unsigned char)*name;
        if (ch >= 'A' && ch <= 'Z') {
            ch = (unsigned char)(ch - 'A' + 'a');
        }
        hash ^= (uint32_t)ch;
        hash *= 16777619u;
        name++;
    }
    return hash;
}

static void hosts_clear(proxy_config_t *config) {
    if (config == NULL) {
        return;
    }
    memset(config->hosts_a_overrides, 0, sizeof(config->hosts_a_overrides));
    config->hosts_a_override_count = 0;
}

static void bootstrap_resolvers_clear(proxy_config_t *config) {
    if (config == NULL) {
        return;
    }
    memset(config->bootstrap_resolvers, 0, sizeof(config->bootstrap_resolvers));
    config->bootstrap_resolver_count = 0;
}

static int normalize_host_name(const char *input, char *output, size_t output_size) {
    if (input == NULL || output == NULL || output_size == 0) {
        return -1;
    }

    size_t start = 0;
    size_t end = strlen(input);

    while (start < end && (unsigned char)input[start] <= ' ') {
        start++;
    }
    while (end > start && (unsigned char)input[end - 1] <= ' ') {
        end--;
    }

    if (start == end) {
        return -1;
    }

    if (input[end - 1] == '.') {
        end--;
    }
    size_t in_len = end - start;
    if (in_len == 0 || in_len >= output_size) {
        return -1;
    }

    size_t label_len = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char ch = (unsigned char)input[start + i];
        if (ch >= 'A' && ch <= 'Z') {
            ch = (unsigned char)(ch - 'A' + 'a');
        }

        if (ch == '.') {
            if (label_len == 0 || label_len > 63) {
                return -1;
            }
            label_len = 0;
            output[i] = (char)ch;
            continue;
        }

        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
            label_len++;
            output[i] = (char)ch;
            continue;
        }

        return -1;
    }

    if (label_len == 0 || label_len > 63) {
        return -1;
    }

    output[in_len] = '\0';
    return 0;
}

static void hosts_add_or_update(proxy_config_t *config, const char *name, uint32_t addr_v4_be) {
    if (config == NULL || name == NULL || *name == '\0') {
        return;
    }

    uint32_t hash = hosts_name_hash(name);
    size_t start = (size_t)(hash % MAX_HOSTS_A_OVERRIDES);
    int free_slot = -1;

    for (size_t probe = 0; probe < MAX_HOSTS_A_OVERRIDES; probe++) {
        size_t idx = (start + probe) % MAX_HOSTS_A_OVERRIDES;
        hosts_a_override_t *entry = &config->hosts_a_overrides[idx];
        if (!entry->in_use) {
            if (free_slot < 0) {
                free_slot = (int)idx;
            }
            break;
        }
        if (entry->name_hash == hash && strcmp(entry->name, name) == 0) {
            entry->addr_v4_be = addr_v4_be;
            return;
        }
    }

    if (free_slot < 0) {
        return;
    }

    hosts_a_override_t *entry = &config->hosts_a_overrides[free_slot];
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->addr_v4_be = addr_v4_be;
    entry->name_hash = hash;
    entry->in_use = 1;
    config->hosts_a_override_count++;
}

static void split_hosts_a_overrides(proxy_config_t *config, const char *value) {
    if (config == NULL || value == NULL) {
        return;
    }

    char buffer[MAX_HOSTS_A_OVERRIDES * 80];
    strncpy(buffer, value, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    hosts_clear(config);

    char *token = strtok(buffer, ",");
    while (token != NULL) {
        trim_in_place(token);
        if (*token != '\0') {
            char *sep = strchr(token, '=');
            if (sep == NULL) {
                sep = strchr(token, ':');
            }

            if (sep != NULL) {
                *sep = '\0';
                char *name_part = token;
                char *addr_part = sep + 1;
                trim_in_place(name_part);
                trim_in_place(addr_part);

                char normalized_name[256];
                struct in_addr addr;
                if (normalize_host_name(name_part, normalized_name, sizeof(normalized_name)) == 0 &&
                    inet_pton(AF_INET, addr_part, &addr) == 1) {
                    hosts_add_or_update(config, normalized_name, addr.s_addr);
                }
            }
        }
        token = strtok(NULL, ",");
    }
}

static void split_bootstrap_resolvers(proxy_config_t *config, const char *value) {
    if (config == NULL || value == NULL) {
        return;
    }

    char buffer[MAX_BOOTSTRAP_RESOLVERS * 32];
    strncpy(buffer, value, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    bootstrap_resolvers_clear(config);

    char *token = strtok(buffer, ",");
    while (token != NULL && config->bootstrap_resolver_count < MAX_BOOTSTRAP_RESOLVERS) {
        trim_in_place(token);
        if (*token != '\0') {
            struct in_addr addr;
            if (inet_pton(AF_INET, token, &addr) == 1) {
                strncpy(
                    config->bootstrap_resolvers[config->bootstrap_resolver_count],
                    token,
                    sizeof(config->bootstrap_resolvers[0]) - 1);
                config->bootstrap_resolver_count++;
            }
        }
        token = strtok(NULL, ",");
    }
}

/* bootstrap resolvers are plain IPv4 DNS resolver addresses */

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

    if (strcmp(key, "upstream_pool_size") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->upstream_pool_size = parsed;
        }
        return;
    }

    if (strcmp(key, "max_inflight_doh") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_doh = parsed;
        }
        return;
    }

    if (strcmp(key, "max_inflight_dot") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_dot = parsed;
        }
        return;
    }

    if (strcmp(key, "max_inflight_doq") == 0) {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_doq = parsed;
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

    if (strcmp(key, "upstreams") == 0) {
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
        return;
    }

    if (strcmp(key, "log_level") == 0) {
        strncpy(config->log_level, value, sizeof(config->log_level) - 1);
        config->log_level[sizeof(config->log_level) - 1] = '\0';
        return;
    }

    if (strcmp(key, "bootstrap_resolvers") == 0) {
        split_bootstrap_resolvers(config, value);
        return;
    }

    if (strcmp(key, "hosts_a") == 0) {
        split_hosts_a_overrides(config, value);
    }
}

static void apply_env_overrides(proxy_config_t *config) {
    /*
     * Environment overrides are applied after file parsing so container/orchestration
     * deploys can override immutable config files without rewriting them.
     */
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

    value = getenv("UPSTREAM_POOL_SIZE");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->upstream_pool_size = parsed;
        }
    }

    value = getenv("MAX_INFLIGHT_DOH");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_doh = parsed;
        }
    }

    value = getenv("MAX_INFLIGHT_DOT");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_dot = parsed;
        }
    }

    value = getenv("MAX_INFLIGHT_DOQ");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->max_inflight_doq = parsed;
        }
    }

    value = getenv("CACHE_CAPACITY");
    if (value != NULL && *value != '\0') {
        int parsed = 0;
        if (parse_int(value, &parsed) == 0 && parsed > 0) {
            config->cache_capacity = parsed;
        }
    }

    value = getenv("UPSTREAMS");
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

    value = getenv("LOG_LEVEL");
    if (value != NULL && *value != '\0') {
        strncpy(config->log_level, value, sizeof(config->log_level) - 1);
        config->log_level[sizeof(config->log_level) - 1] = '\0';
    }

    value = getenv("HOSTS_A");
    if (value != NULL && *value != '\0') {
        split_hosts_a_overrides(config, value);
    }

    value = getenv("BOOTSTRAP_RESOLVERS");
    if (value != NULL && *value != '\0') {
        split_bootstrap_resolvers(config, value);
    }
}

static void set_defaults(proxy_config_t *config) {
    memset(config, 0, sizeof(*config));
    strncpy(config->listen_addr, "0.0.0.0", sizeof(config->listen_addr) - 1);
    config->listen_port = 53;
    config->upstream_timeout_ms = 2500;
    config->upstream_pool_size = 6;
    config->max_inflight_doh = 4;
    config->max_inflight_dot = 1;
    config->max_inflight_doq = 1;
    config->cache_capacity = 1024;

#if UPSTREAM_DOH_ENABLED
    strncpy(config->upstream_urls[0], "https://cloudflare-dns.com/dns-query", MAX_URL_LEN - 1);
    strncpy(config->upstream_urls[1], "https://dns.google/dns-query", MAX_URL_LEN - 1);
    config->upstream_count = 2;
#elif UPSTREAM_DOT_ENABLED
    strncpy(config->upstream_urls[0], "tls://cloudflare-dns.com:853", MAX_URL_LEN - 1);
    strncpy(config->upstream_urls[1], "tls://dns.google:853", MAX_URL_LEN - 1);
    config->upstream_count = 2;
#elif UPSTREAM_DOQ_ENABLED
    strncpy(config->upstream_urls[0], "quic://dns.adguard-dns.com:853", MAX_URL_LEN - 1);
    strncpy(config->upstream_urls[1], "quic://dns.adguard-dns.com:8853", MAX_URL_LEN - 1);
    config->upstream_count = 2;
#else
    config->upstream_count = 0;
#endif

    strncpy(config->config_path, "dns-encrypted-proxy.conf", sizeof(config->config_path) - 1);

    config->tcp_idle_timeout_ms = 10000;
    config->tcp_max_clients = 256;
    config->tcp_max_queries_per_conn = 0;
    config->metrics_enabled = 1;
    config->metrics_port = 9090;
    strncpy(config->log_level, "INFO", sizeof(config->log_level) - 1);
    bootstrap_resolvers_clear(config);
    strncpy(config->bootstrap_resolvers[0], "8.8.8.8", sizeof(config->bootstrap_resolvers[0]) - 1);
    strncpy(config->bootstrap_resolvers[1], "1.1.1.1", sizeof(config->bootstrap_resolvers[1]) - 1);
    config->bootstrap_resolver_count = 2;
    hosts_clear(config);
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
        const char *env_path = getenv("DNS_ENCRYPTED_PROXY_CONFIG");
        if (env_path != NULL && *env_path != '\0') {
            path = env_path;
        } else {
            path = config->config_path;
        }
    }

    /*
     * |path| can alias config->config_path when defaults are used, so copy
     * through a temporary buffer to avoid undefined overlap behavior.
     */
    char selected_path[sizeof(config->config_path)];
    strncpy(selected_path, path, sizeof(selected_path) - 1);
    selected_path[sizeof(selected_path) - 1] = '\0';
    memcpy(config->config_path, selected_path, sizeof(selected_path));

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

    if (config->upstream_pool_size <= 0) {
        return -1;
    }

    if (config->max_inflight_doh <= 0 || config->max_inflight_dot <= 0 || config->max_inflight_doq <= 0) {
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
    fprintf(out, "  upstream_pool_size=%d\n", config->upstream_pool_size);
    fprintf(out, "  max_inflight_doh=%d\n", config->max_inflight_doh);
    fprintf(out, "  max_inflight_dot=%d\n", config->max_inflight_dot);
    fprintf(out, "  max_inflight_doq=%d\n", config->max_inflight_doq);
    fprintf(out, "  cache_capacity=%d\n", config->cache_capacity);
    fprintf(out, "  tcp_idle_timeout_ms=%d\n", config->tcp_idle_timeout_ms);
    fprintf(out, "  tcp_max_clients=%d\n", config->tcp_max_clients);
    fprintf(out, "  tcp_max_queries_per_conn=%d\n", config->tcp_max_queries_per_conn);
    fprintf(out, "  metrics_enabled=%d\n", config->metrics_enabled);
    fprintf(out, "  metrics_port=%d\n", config->metrics_port);
    fprintf(out, "  log_level=%s\n", config->log_level);
    fprintf(out, "  bootstrap_resolvers=");
    for (int i = 0; i < config->bootstrap_resolver_count; i++) {
        fprintf(out, "%s%s", config->bootstrap_resolvers[i], (i + 1 == config->bootstrap_resolver_count) ? "" : ",");
    }
    fprintf(out, "\n");
    fprintf(out, "  hosts_a=");
    int wrote_hosts = 0;
    for (int i = 0; i < MAX_HOSTS_A_OVERRIDES; i++) {
        const hosts_a_override_t *entry = &config->hosts_a_overrides[i];
        if (!entry->in_use) {
            continue;
        }
        struct in_addr addr;
        addr.s_addr = entry->addr_v4_be;
        fprintf(out, "%s%s=%s", wrote_hosts ? "," : "", entry->name, inet_ntoa(addr));
        wrote_hosts = 1;
    }
    fprintf(out, "\n");
    fprintf(out, "  upstreams=");
    for (int i = 0; i < config->upstream_count; i++) {
        fprintf(out, "%s%s", config->upstream_urls[i], (i + 1 == config->upstream_count) ? "" : ",");
    }
    fprintf(out, "\n");
}

int config_lookup_hosts_a(const proxy_config_t *config, const char *name, uint32_t *addr_v4_be_out) {
    if (config == NULL || name == NULL || *name == '\0') {
        return 0;
    }

    char normalized[256];
    if (normalize_host_name(name, normalized, sizeof(normalized)) != 0) {
        return 0;
    }

    uint32_t hash = hosts_name_hash(normalized);
    size_t start = (size_t)(hash % MAX_HOSTS_A_OVERRIDES);

    for (size_t probe = 0; probe < MAX_HOSTS_A_OVERRIDES; probe++) {
        size_t idx = (start + probe) % MAX_HOSTS_A_OVERRIDES;
        const hosts_a_override_t *entry = &config->hosts_a_overrides[idx];
        if (!entry->in_use) {
            return 0;
        }
        if (entry->name_hash == hash && strcmp(entry->name, normalized) == 0) {
            if (addr_v4_be_out != NULL) {
                *addr_v4_be_out = entry->addr_v4_be;
            }
            return 1;
        }
    }

    return 0;
}
