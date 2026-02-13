#include "dns_message.h"

#include <limits.h>
#include <string.h>

#define DNS_HEADER_SIZE 12
#define DNS_TYPE_OPT 41
#define DNS_QUESTION_KEY_CAPACITY 512
#define DNS_CACHE_KEY_VERSION 1
#define DNS_UDP_LEGACY_PAYLOAD 512
#define DNS_UDP_MAX_SAFE_PAYLOAD 4096
#define DNS_EDNS_OPT_COOKIE 10
#define DNS_EDNS_OPT_PADDING 12

static uint16_t read_u16(const uint8_t *ptr) {
    return (uint16_t)((ptr[0] << 8) | ptr[1]);
}

static uint32_t read_u32(const uint8_t *ptr) {
    return ((uint32_t)ptr[0] << 24) |
           ((uint32_t)ptr[1] << 16) |
           ((uint32_t)ptr[2] << 8) |
           (uint32_t)ptr[3];
}

static void write_u16(uint8_t *ptr, uint16_t value) {
    ptr[0] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[1] = (uint8_t)(value & 0xFFu);
}

static void write_u32(uint8_t *ptr, uint32_t value) {
    ptr[0] = (uint8_t)((value >> 24) & 0xFFu);
    ptr[1] = (uint8_t)((value >> 16) & 0xFFu);
    ptr[2] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[3] = (uint8_t)(value & 0xFFu);
}

static int dns_skip_name(const uint8_t *message, size_t message_len, size_t *offset) {
    size_t pos = *offset;
    int steps = 0;

    while (pos < message_len) {
        if (++steps > 255) {
            return -1;
        }

        uint8_t label_len = message[pos];
        if (label_len == 0) {
            pos += 1;
            *offset = pos;
            return 0;
        }

        if ((label_len & 0xC0u) == 0xC0u) {
            if (pos + 1 >= message_len) {
                return -1;
            }
            pos += 2;
            *offset = pos;
            return 0;
        }

        if ((label_len & 0xC0u) != 0) {
            return -1;
        }

        pos += 1;
        if (pos + label_len > message_len) {
            return -1;
        }
        pos += label_len;
    }

    return -1;
}

static int dns_copy_name_canonical(
    const uint8_t *message,
    size_t message_len,
    size_t *offset,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len_out) {
    if (message == NULL || offset == NULL || out == NULL || out_len_out == NULL) {
        return -1;
    }

    size_t pos = *offset;
    size_t consumed = pos;
    size_t out_len = 0;
    int jumped = 0;
    int steps = 0;

    while (pos < message_len) {
        if (++steps > 255) {
            return -1;
        }

        uint8_t label_len = message[pos];
        if (label_len == 0) {
            if (out_len + 1 > out_capacity) {
                return -1;
            }
            out[out_len++] = 0;

            if (!jumped) {
                consumed = pos + 1;
            }

            *offset = consumed;
            *out_len_out = out_len;
            return 0;
        }

        if ((label_len & 0xC0u) == 0xC0u) {
            if (pos + 1 >= message_len) {
                return -1;
            }

            uint16_t pointer = (uint16_t)(((label_len & 0x3Fu) << 8) | message[pos + 1]);
            if ((size_t)pointer >= message_len) {
                return -1;
            }

            if (!jumped) {
                consumed = pos + 2;
                jumped = 1;
            }

            pos = (size_t)pointer;
            continue;
        }

        if ((label_len & 0xC0u) != 0 || label_len > 63) {
            return -1;
        }

        if (pos + 1 + label_len > message_len) {
            return -1;
        }
        if (out_len + 1 + label_len > out_capacity) {
            return -1;
        }

        out[out_len++] = label_len;
        for (uint8_t i = 0; i < label_len; i++) {
            uint8_t ch = message[pos + 1 + i];
            if (ch >= 'A' && ch <= 'Z') {
                ch = (uint8_t)(ch - 'A' + 'a');
            }
            out[out_len++] = ch;
        }

        pos += 1 + label_len;
        if (!jumped) {
            consumed = pos;
        }
    }

    return -1;
}

static int dns_message_end_offset(const uint8_t *message, size_t message_len, size_t *end_offset_out) {
    if (message == NULL || end_offset_out == NULL || message_len < DNS_HEADER_SIZE) {
        return -1;
    }

    uint16_t qdcount = read_u16(message + 4);
    uint16_t ancount = read_u16(message + 6);
    uint16_t nscount = read_u16(message + 8);
    uint16_t arcount = read_u16(message + 10);
    uint32_t rr_total = (uint32_t)ancount + (uint32_t)nscount + (uint32_t)arcount;

    if (rr_total > UINT16_MAX) {
        return -1;
    }

    size_t offset = DNS_HEADER_SIZE;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > message_len) {
            return -1;
        }
        offset += 4;
    }

    for (uint32_t i = 0; i < rr_total; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 10 > message_len) {
            return -1;
        }

        uint16_t rdlength = read_u16(message + offset + 8);
        offset += 10;
        if (offset + rdlength > message_len) {
            return -1;
        }
        offset += rdlength;
    }

    *end_offset_out = offset;
    return 0;
}

static int dns_question_sections_equal(
    const uint8_t *query,
    size_t query_len,
    const uint8_t *response,
    size_t response_len) {
    if (query_len < DNS_HEADER_SIZE || response_len < DNS_HEADER_SIZE) {
        return -1;
    }

    uint16_t query_qdcount = read_u16(query + 4);
    uint16_t response_qdcount = read_u16(response + 4);
    if (query_qdcount != response_qdcount) {
        return -1;
    }

    size_t query_offset = DNS_HEADER_SIZE;
    size_t response_offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < query_qdcount; i++) {
        uint8_t query_name[DNS_QUESTION_KEY_CAPACITY];
        uint8_t response_name[DNS_QUESTION_KEY_CAPACITY];
        size_t query_name_len = 0;
        size_t response_name_len = 0;

        if (dns_copy_name_canonical(query, query_len, &query_offset, query_name, sizeof(query_name), &query_name_len) != 0) {
            return -1;
        }
        if (dns_copy_name_canonical(response, response_len, &response_offset, response_name, sizeof(response_name), &response_name_len) != 0) {
            return -1;
        }

        if (query_name_len != response_name_len || memcmp(query_name, response_name, query_name_len) != 0) {
            return -1;
        }

        if (query_offset + 4 > query_len || response_offset + 4 > response_len) {
            return -1;
        }
        if (memcmp(query + query_offset, response + response_offset, 4) != 0) {
            return -1;
        }

        query_offset += 4;
        response_offset += 4;
    }

    return 0;
}

int dns_extract_question_key(const uint8_t *query, size_t query_len, uint8_t *key_out, size_t key_capacity, size_t *key_len_out) {
    if (query == NULL || key_out == NULL || key_len_out == NULL || query_len < DNS_HEADER_SIZE) {
        return -1;
    }

    *key_len_out = 0;

    uint16_t flags = read_u16(query + 2);
    uint16_t qdcount = read_u16(query + 4);
    uint16_t ancount = read_u16(query + 6);
    uint16_t nscount = read_u16(query + 8);
    uint16_t arcount = read_u16(query + 10);
    if (qdcount == 0) {
        return -1;
    }
    if (ancount != 0 || nscount != 0) {
        return -1;
    }

    uint16_t opcode = (uint16_t)(flags & 0x7800u);
    if (opcode != 0) {
        return -1;
    }

    size_t offset = DNS_HEADER_SIZE;
    size_t key_len = 0;

    if (key_capacity < 5) {
        return -1;
    }
    key_out[key_len++] = DNS_CACHE_KEY_VERSION;

    /* Include query-level flags that influence resolver behavior. */
    uint16_t key_flags = (uint16_t)(flags & (0x0100u | 0x0020u | 0x0010u | 0x7800u)); /* RD, AD, CD, OPCODE */
    write_u16(key_out + key_len, key_flags);
    key_len += 2;

    write_u16(key_out + key_len, qdcount);
    key_len += 2;

    for (uint16_t i = 0; i < qdcount; i++) {
        size_t name_len = 0;
        if (dns_copy_name_canonical(query, query_len, &offset, key_out + key_len, key_capacity - key_len, &name_len) != 0) {
            return -1;
        }
        key_len += name_len;

        if (offset + 4 > query_len || key_len + 4 > key_capacity) {
            return -1;
        }
        memcpy(key_out + key_len, query + offset, 4); /* QTYPE + QCLASS */
        key_len += 4;
        offset += 4;
    }

    uint8_t opt_present = 0;
    uint16_t opt_udp_payload = 0;
    uint8_t opt_version = 0;
    uint16_t opt_z = 0;
    const uint8_t *opt_rdata = NULL;
    uint16_t opt_rdata_len = 0;

    for (uint16_t i = 0; i < arcount; i++) {
        size_t rr_name_end = offset;
        if (dns_skip_name(query, query_len, &rr_name_end) != 0) {
            return -1;
        }
        offset = rr_name_end;

        if (offset + 10 > query_len) {
            return -1;
        }

        uint16_t rr_type = read_u16(query + offset);
        uint16_t rr_class = read_u16(query + offset + 2);
        uint32_t rr_ttl = read_u32(query + offset + 4);
        uint16_t rr_rdlength = read_u16(query + offset + 8);
        offset += 10;

        if (offset + rr_rdlength > query_len) {
            return -1;
        }

        if (rr_type == DNS_TYPE_OPT) {
            if (opt_present) {
                return -1;
            }
            opt_present = 1;
            opt_udp_payload = rr_class;
            opt_version = (uint8_t)((rr_ttl >> 16) & 0xFFu);
            opt_z = (uint16_t)(rr_ttl & 0xFFFFu); /* includes DO bit and Z bits */
            opt_rdata = query + offset;
            opt_rdata_len = rr_rdlength;
        } else {
            /* Conservative: skip caching when additional records beyond OPT are present. */
            return -1;
        }

        offset += rr_rdlength;
    }

    if (offset != query_len) {
        return -1;
    }

    if (key_len + 1 > key_capacity) {
        return -1;
    }
    key_out[key_len++] = opt_present;

    if (opt_present) {
        if (key_len + 7 > key_capacity) {
            return -1;
        }
        write_u16(key_out + key_len, opt_udp_payload);
        key_len += 2;
        key_out[key_len++] = opt_version;
        write_u16(key_out + key_len, opt_z);
        key_len += 2;

        size_t opt_len_pos = key_len;
        write_u16(key_out + key_len, 0);
        key_len += 2;

        uint16_t filtered_len = 0;
        size_t opt_offset = 0;
        while (opt_offset < opt_rdata_len) {
            if (opt_offset + 4 > opt_rdata_len) {
                return -1;
            }

            uint16_t code = read_u16(opt_rdata + opt_offset);
            uint16_t len = read_u16(opt_rdata + opt_offset + 2);
            size_t option_total = (size_t)len + 4;
            if (opt_offset + option_total > opt_rdata_len) {
                return -1;
            }

            /* Ignore volatile client options that should not fragment cache keys. */
            if (code != DNS_EDNS_OPT_COOKIE && code != DNS_EDNS_OPT_PADDING) {
                if (key_len + option_total > key_capacity || filtered_len > UINT16_MAX - option_total) {
                    return -1;
                }
                memcpy(key_out + key_len, opt_rdata + opt_offset, option_total);
                key_len += option_total;
                filtered_len = (uint16_t)(filtered_len + option_total);
            }

            opt_offset += option_total;
        }

        write_u16(key_out + opt_len_pos, filtered_len);
    }

    if (key_len == 0) {
        return -1;
    }

    *key_len_out = key_len;
    return 0;
}

int dns_question_section_length(const uint8_t *message, size_t message_len, size_t *section_len_out) {
    if (message == NULL || section_len_out == NULL || message_len < DNS_HEADER_SIZE) {
        return -1;
    }

    uint16_t qdcount = read_u16(message + 4);
    size_t offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > message_len) {
            return -1;
        }
        offset += 4;
    }

    *section_len_out = offset - DNS_HEADER_SIZE;
    return 0;
}

size_t dns_udp_payload_limit_for_query(const uint8_t *query, size_t query_len) {
    if (query == NULL || query_len < DNS_HEADER_SIZE) {
        return DNS_UDP_LEGACY_PAYLOAD;
    }

    uint16_t qdcount = read_u16(query + 4);
    uint16_t ancount = read_u16(query + 6);
    uint16_t nscount = read_u16(query + 8);
    uint16_t arcount = read_u16(query + 10);
    uint32_t rr_total = (uint32_t)ancount + (uint32_t)nscount + (uint32_t)arcount;
    if (rr_total > UINT16_MAX) {
        return DNS_UDP_LEGACY_PAYLOAD;
    }

    size_t offset = DNS_HEADER_SIZE;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(query, query_len, &offset) != 0) {
            return DNS_UDP_LEGACY_PAYLOAD;
        }
        if (offset + 4 > query_len) {
            return DNS_UDP_LEGACY_PAYLOAD;
        }
        offset += 4;
    }

    uint16_t advertised = 0;
    for (uint32_t i = 0; i < rr_total; i++) {
        if (dns_skip_name(query, query_len, &offset) != 0) {
            return DNS_UDP_LEGACY_PAYLOAD;
        }
        if (offset + 10 > query_len) {
            return DNS_UDP_LEGACY_PAYLOAD;
        }

        uint16_t rr_type = read_u16(query + offset);
        uint16_t rr_class = read_u16(query + offset + 2);
        uint16_t rdlength = read_u16(query + offset + 8);
        offset += 10;

        if (offset + rdlength > query_len) {
            return DNS_UDP_LEGACY_PAYLOAD;
        }

        if (rr_type == DNS_TYPE_OPT) {
            advertised = rr_class;
            break;
        }

        offset += rdlength;
    }

    size_t limit = DNS_UDP_LEGACY_PAYLOAD;
    if (advertised > 0) {
        limit = advertised < DNS_UDP_LEGACY_PAYLOAD ? DNS_UDP_LEGACY_PAYLOAD : advertised;
    }
    if (limit > DNS_UDP_MAX_SAFE_PAYLOAD) {
        limit = DNS_UDP_MAX_SAFE_PAYLOAD;
    }

    return limit;
}

static int dns_iterate_rrs(const uint8_t *message, size_t message_len, uint16_t *answer_count_out, size_t *rr_section_offset_out) {
    if (message_len < DNS_HEADER_SIZE) {
        return -1;
    }

    uint16_t qdcount = read_u16(message + 4);
    uint16_t ancount = read_u16(message + 6);
    uint16_t nscount = read_u16(message + 8);
    uint16_t arcount = read_u16(message + 10);
    uint32_t rr_total = (uint32_t)ancount + (uint32_t)nscount + (uint32_t)arcount;

    if (rr_total > UINT16_MAX) {
        return -1;
    }

    size_t offset = DNS_HEADER_SIZE;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > message_len) {
            return -1;
        }
        offset += 4;
    }

    if (answer_count_out != NULL) {
        *answer_count_out = (uint16_t)rr_total;
    }
    if (rr_section_offset_out != NULL) {
        *rr_section_offset_out = offset;
    }

    return 0;
}

#define DNS_TYPE_SOA 6

static int dns_is_negative_response(const uint8_t *message, size_t message_len) {
    if (message_len < DNS_HEADER_SIZE) {
        return 0;
    }
    uint16_t flags = read_u16(message + 2);
    uint16_t rcode = flags & 0x000Fu;
    uint16_t ancount = read_u16(message + 6);

    if (rcode == 3) {
        return 1;
    }
    if (rcode == 0 && ancount == 0) {
        return 1;
    }
    return 0;
}

static uint32_t dns_extract_soa_minimum(const uint8_t *message, size_t message_len) {
    if (message_len < DNS_HEADER_SIZE) {
        return UINT32_MAX;
    }

    uint16_t qdcount = read_u16(message + 4);
    uint16_t ancount = read_u16(message + 6);
    uint16_t nscount = read_u16(message + 8);

    size_t offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return UINT32_MAX;
        }
        if (offset + 4 > message_len) {
            return UINT32_MAX;
        }
        offset += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return UINT32_MAX;
        }
        if (offset + 10 > message_len) {
            return UINT32_MAX;
        }
        uint16_t rdlength = read_u16(message + offset + 8);
        offset += 10 + rdlength;
        if (offset > message_len) {
            return UINT32_MAX;
        }
    }

    for (uint16_t i = 0; i < nscount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return UINT32_MAX;
        }
        if (offset + 10 > message_len) {
            return UINT32_MAX;
        }

        uint16_t rr_type = read_u16(message + offset);
        uint32_t rr_ttl = read_u32(message + offset + 4);
        uint16_t rdlength = read_u16(message + offset + 8);
        size_t rdata_start = offset + 10;

        if (rdata_start + rdlength > message_len) {
            return UINT32_MAX;
        }

        if (rr_type == DNS_TYPE_SOA && rdlength >= 20) {
            size_t rdata_offset = rdata_start;
            if (dns_skip_name(message, message_len, &rdata_offset) != 0) {
                return UINT32_MAX;
            }
            if (dns_skip_name(message, message_len, &rdata_offset) != 0) {
                return UINT32_MAX;
            }
            if (rdata_offset + 20 > rdata_start + rdlength) {
                return UINT32_MAX;
            }
            uint32_t soa_minimum = read_u32(message + rdata_offset + 16);
            return (soa_minimum < rr_ttl) ? soa_minimum : rr_ttl;
        }

        offset = rdata_start + rdlength;
    }

    return UINT32_MAX;
}

uint32_t dns_response_min_ttl(const uint8_t *message, size_t message_len, int *ok_out) {
    if (ok_out != NULL) {
        *ok_out = 0;
    }

    if (dns_is_negative_response(message, message_len)) {
        uint32_t neg_ttl = dns_extract_soa_minimum(message, message_len);
        if (neg_ttl != UINT32_MAX) {
            if (ok_out != NULL) {
                *ok_out = 1;
            }
            return neg_ttl;
        }
    }

    uint16_t rr_total = 0;
    size_t offset = 0;
    if (dns_iterate_rrs(message, message_len, &rr_total, &offset) != 0) {
        return 0;
    }

    if (rr_total == 0) {
        if (ok_out != NULL) {
            *ok_out = 1;
        }
        return 0;
    }

    uint32_t min_ttl = UINT32_MAX;
    uint32_t ttl_rr_count = 0;
    for (uint16_t i = 0; i < rr_total; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return 0;
        }
        if (offset + 10 > message_len) {
            return 0;
        }

        uint16_t rr_type = read_u16(message + offset);
        uint32_t ttl = read_u32(message + offset + 4);
        if (rr_type != DNS_TYPE_OPT) {
            if (ttl < min_ttl) {
                min_ttl = ttl;
            }
            ttl_rr_count++;
        }

        uint16_t rdlength = read_u16(message + offset + 8);
        offset += 10;
        if (offset + rdlength > message_len) {
            return 0;
        }
        offset += rdlength;
    }

    if (ok_out != NULL) {
        *ok_out = 1;
    }

    if (ttl_rr_count == 0 || min_ttl == UINT32_MAX) {
        return 0;
    }

    return min_ttl;
}

int dns_adjust_response_ttls(uint8_t *message, size_t message_len, uint32_t age_seconds) {
    uint16_t rr_total = 0;
    size_t offset = 0;
    if (dns_iterate_rrs(message, message_len, &rr_total, &offset) != 0) {
        return -1;
    }

    for (uint16_t i = 0; i < rr_total; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 10 > message_len) {
            return -1;
        }

        uint16_t rr_type = read_u16(message + offset);
        if (rr_type != DNS_TYPE_OPT) {
            uint32_t ttl = read_u32(message + offset + 4);
            uint32_t adjusted = (age_seconds >= ttl) ? 0u : (ttl - age_seconds);
            write_u32(message + offset + 4, adjusted);
        }

        uint16_t rdlength = read_u16(message + offset + 8);
        offset += 10;
        if (offset + rdlength > message_len) {
            return -1;
        }
        offset += rdlength;
    }

    return 0;
}

static int dns_validate_section_counts(const uint8_t *message, size_t message_len) {
    if (message == NULL || message_len < DNS_HEADER_SIZE) {
        return -1;
    }

    uint16_t qdcount = read_u16(message + 4);
    uint16_t ancount = read_u16(message + 6);
    uint16_t nscount = read_u16(message + 8);
    uint16_t arcount = read_u16(message + 10);

    size_t offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > message_len) {
            return -1;
        }
        offset += 4;
    }

    uint16_t section_counts[3] = {ancount, nscount, arcount};
    for (int section = 0; section < 3; section++) {
        for (uint16_t i = 0; i < section_counts[section]; i++) {
            if (dns_skip_name(message, message_len, &offset) != 0) {
                return -1;
            }
            if (offset + 10 > message_len) {
                return -1;
            }
            uint16_t rdlength = read_u16(message + offset + 8);
            offset += 10;
            if (offset + rdlength > message_len) {
                return -1;
            }
            offset += rdlength;
        }
    }

    if (offset != message_len) {
        return -1;
    }

    return 0;
}

int dns_response_is_cacheable(const uint8_t *response, size_t response_len) {
    if (response == NULL || response_len < DNS_HEADER_SIZE) {
        return 0;
    }

    uint16_t flags = read_u16(response + 2);

    if (flags & 0x0200u) {
        return 0;
    }

    uint16_t rcode = flags & 0x000Fu;
    if (rcode != 0 && rcode != 3) {
        return 0;
    }

    if (dns_validate_section_counts(response, response_len) != 0) {
        return 0;
    }

    return 1;
}

int dns_validate_response_for_query(const uint8_t *query, size_t query_len, const uint8_t *response, size_t response_len) {
    if (query == NULL || response == NULL || query_len < DNS_HEADER_SIZE || response_len < DNS_HEADER_SIZE) {
        return -1;
    }

    size_t query_end = 0;
    size_t response_end = 0;
    if (dns_message_end_offset(query, query_len, &query_end) != 0 || query_end != query_len) {
        return -1;
    }
    if (dns_message_end_offset(response, response_len, &response_end) != 0 || response_end != response_len) {
        return -1;
    }

    uint16_t query_flags = read_u16(query + 2);
    uint16_t response_flags = read_u16(response + 2);

    if ((response_flags & 0x8000u) == 0) {
        return -1;
    }

    if ((response_flags & 0x7800u) != (query_flags & 0x7800u)) {
        return -1;
    }

    if (dns_validate_section_counts(response, response_len) != 0) {
        return -1;
    }

    if (dns_question_sections_equal(query, query_len, response, response_len) != 0) {
        return -1;
    }

    return 0;
}
