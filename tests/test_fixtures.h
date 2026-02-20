#ifndef TEST_FIXTURES_H
#define TEST_FIXTURES_H

#include <stdint.h>
#include <stddef.h>

/*
 * DNS packet fixtures for testing.
 * These are real DNS wire-format packets for use in unit and integration tests.
 */

/* Standard DNS query for www.example.com A record (no EDNS) */
static const uint8_t DNS_QUERY_WWW_EXAMPLE_COM_A[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x01, 0x00,             /* Flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,                   /* Root label */
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};
static const size_t DNS_QUERY_WWW_EXAMPLE_COM_A_LEN = sizeof(DNS_QUERY_WWW_EXAMPLE_COM_A);

/* DNS query for www.example.com A record with EDNS (4096 byte buffer) */
static const uint8_t DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS[] = {
    /* Header */
    0x56, 0x78,             /* ID */
    0x01, 0x00,             /* Flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x01,             /* ARCOUNT: 1 (OPT record) */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* OPT record (EDNS) */
    0x00,                   /* Root name */
    0x00, 0x29,             /* TYPE: OPT (41) */
    0x10, 0x00,             /* CLASS: UDP payload size (4096) */
    0x00, 0x00, 0x00, 0x00, /* TTL: extended RCODE, version, flags */
    0x00, 0x00              /* RDLENGTH: 0 */
};
static const size_t DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN = sizeof(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS);

/* DNS query for www.example.com with EDNS and DO bit (DNSSEC OK) */
static const uint8_t DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_DO[] = {
    /* Header */
    0xAB, 0xCD,             /* ID */
    0x01, 0x20,             /* Flags: RD=1, AD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x01,             /* ARCOUNT: 1 (OPT record) */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* OPT record with DO bit */
    0x00,                   /* Root name */
    0x00, 0x29,             /* TYPE: OPT (41) */
    0x10, 0x00,             /* CLASS: UDP payload size (4096) */
    0x00, 0x00, 0x80, 0x00, /* TTL: DO=1 */
    0x00, 0x00              /* RDLENGTH: 0 */
};
static const size_t DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_DO_LEN = sizeof(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_DO);

/* DNS response for www.example.com A record (93.184.216.34) */
static const uint8_t DNS_RESPONSE_WWW_EXAMPLE_COM_A[] = {
    /* Header */
    0x12, 0x34,             /* ID (matches query) */
    0x81, 0x80,             /* Flags: QR=1, RD=1, RA=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x01,             /* ANCOUNT: 1 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* Answer: www.example.com A 93.184.216.34 TTL=300 */
    0xC0, 0x0C,             /* Name pointer to question */
    0x00, 0x01,             /* TYPE: A */
    0x00, 0x01,             /* CLASS: IN */
    0x00, 0x00, 0x01, 0x2C, /* TTL: 300 seconds */
    0x00, 0x04,             /* RDLENGTH: 4 */
    0x5D, 0xB8, 0xD8, 0x22  /* RDATA: 93.184.216.34 */
};
static const size_t DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN = sizeof(DNS_RESPONSE_WWW_EXAMPLE_COM_A);

/* NXDOMAIN response for nonexistent.example.com */
static const uint8_t DNS_RESPONSE_NXDOMAIN[] = {
    /* Header */
    0x99, 0x99,             /* ID */
    0x81, 0x83,             /* Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN) */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x01,             /* NSCOUNT: 1 (SOA) */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: nonexistent.example.com A IN */
    0x0B, 'n', 'o', 'n', 'e', 'x', 'i', 's', 't', 'e', 'n', 't',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* Authority: example.com SOA */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x06,             /* TYPE: SOA */
    0x00, 0x01,             /* CLASS: IN */
    0x00, 0x00, 0x00, 0x3C, /* TTL: 60 seconds */
    0x00, 0x2C,             /* RDLENGTH: 44 (3+13+8+20) */
    /* SOA RDATA: ns.example.com admin.example.com 2024010100 3600 600 604800 60 */
    0x02, 'n', 's',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x05, 'a', 'd', 'm', 'i', 'n',
    0xC0, 0x18,             /* Pointer to example.com at offset 24 */
    0x78, 0x7A, 0x41, 0x24, /* Serial: 2024010100 */
    0x00, 0x00, 0x0E, 0x10, /* Refresh: 3600 */
    0x00, 0x00, 0x02, 0x58, /* Retry: 600 */
    0x00, 0x09, 0x3A, 0x80, /* Expire: 604800 */
    0x00, 0x00, 0x00, 0x3C  /* Minimum: 60 (negative cache TTL) */
};
static const size_t DNS_RESPONSE_NXDOMAIN_LEN = sizeof(DNS_RESPONSE_NXDOMAIN);

/* SERVFAIL response */
static const uint8_t DNS_RESPONSE_SERVFAIL[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x81, 0x82,             /* Flags: QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL) */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};
static const size_t DNS_RESPONSE_SERVFAIL_LEN = sizeof(DNS_RESPONSE_SERVFAIL);

/* Truncated response (TC bit set) */
static const uint8_t DNS_RESPONSE_TRUNCATED[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x83, 0x80,             /* Flags: QR=1, TC=1, RD=1, RA=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,             /* ANCOUNT: 0 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};
static const size_t DNS_RESPONSE_TRUNCATED_LEN = sizeof(DNS_RESPONSE_TRUNCATED);

/* Malformed packet: truncated header */
static const uint8_t DNS_MALFORMED_SHORT_HEADER[] = {
    0x12, 0x34, 0x01, 0x00, 0x00  /* Only 5 bytes, header needs 12 */
};
static const size_t DNS_MALFORMED_SHORT_HEADER_LEN = sizeof(DNS_MALFORMED_SHORT_HEADER);

/* Malformed packet: label length exceeds packet */
static const uint8_t DNS_MALFORMED_BAD_LABEL[] = {
    0x12, 0x34,             /* ID */
    0x01, 0x00,             /* Flags */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x40, 'x', 'x', 'x'     /* Label claims 64 bytes but only 3 follow */
};
static const size_t DNS_MALFORMED_BAD_LABEL_LEN = sizeof(DNS_MALFORMED_BAD_LABEL);

/* DNS query for example.com AAAA record */
static const uint8_t DNS_QUERY_EXAMPLE_COM_AAAA[] = {
    /* Header */
    0xAA, 0xBB,             /* ID */
    0x01, 0x00,             /* Flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    /* Question: example.com AAAA IN */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x1C,             /* QTYPE: AAAA (28) */
    0x00, 0x01              /* QCLASS: IN */
};
static const size_t DNS_QUERY_EXAMPLE_COM_AAAA_LEN = sizeof(DNS_QUERY_EXAMPLE_COM_AAAA);

/* DNS query with uppercase letters (for case-insensitivity testing) */
static const uint8_t DNS_QUERY_UPPERCASE[] = {
    /* Header */
    0xCC, 0xDD,             /* ID */
    0x01, 0x00,             /* Flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    /* Question: WWW.EXAMPLE.COM A IN (uppercase) */
    0x03, 'W', 'W', 'W',
    0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E',
    0x03, 'C', 'O', 'M',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};
static const size_t DNS_QUERY_UPPERCASE_LEN = sizeof(DNS_QUERY_UPPERCASE);

/* Response with multiple answer records and varying TTLs */
static const uint8_t DNS_RESPONSE_MULTI_ANSWER[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x81, 0x80,             /* Flags: QR=1, RD=1, RA=1 */
    0x00, 0x01,             /* QDCOUNT: 1 */
    0x00, 0x03,             /* ANCOUNT: 3 */
    0x00, 0x00,             /* NSCOUNT: 0 */
    0x00, 0x00,             /* ARCOUNT: 0 */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* Answer 1: TTL=300 */
    0xC0, 0x0C,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2C, /* TTL: 300 */
    0x00, 0x04,
    0x5D, 0xB8, 0xD8, 0x22,
    /* Answer 2: TTL=100 (minimum) */
    0xC0, 0x0C,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x64, /* TTL: 100 */
    0x00, 0x04,
    0x5D, 0xB8, 0xD8, 0x23,
    /* Answer 3: TTL=600 */
    0xC0, 0x0C,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x02, 0x58, /* TTL: 600 */
    0x00, 0x04,
    0x5D, 0xB8, 0xD8, 0x24
};
static const size_t DNS_RESPONSE_MULTI_ANSWER_LEN = sizeof(DNS_RESPONSE_MULTI_ANSWER);

#endif /* TEST_FIXTURES_H */
