#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

int dns_extract_question_key(const uint8_t *query, size_t query_len, uint8_t *key_out, size_t key_capacity, size_t *key_len_out);
int dns_question_section_length(const uint8_t *message, size_t message_len, size_t *section_len_out);
size_t dns_udp_payload_limit_for_query(const uint8_t *query, size_t query_len);
uint32_t dns_response_min_ttl(const uint8_t *message, size_t message_len, int *ok_out);
int dns_adjust_response_ttls(uint8_t *message, size_t message_len, uint32_t age_seconds);
int dns_validate_response_for_query(const uint8_t *query, size_t query_len, const uint8_t *response, size_t response_len);

#endif
