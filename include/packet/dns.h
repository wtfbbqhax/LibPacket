#ifndef LIBPACKET_DECODE_DNS_H
#define LIBPACKET_DECODE_DNS_H

// See RFC 1035,
// https://datatracker.ietf.org/doc/html/rfc1035

#include <string>
#include <cstdint>

struct dns_stats {
    uint64_t dns_tooshort;
    uint64_t dns_too_many_queries; // > 256 DNS Questions
    uint64_t dns_too_many_answers; // > 256 DNS Answers
};

extern struct dns_stats s_dns_stats;

// DNS Header
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

struct dns_query {
    std::string label;
    // Store QTYPE and QCLASS (assuming a structure in Packet to store this information)
    uint16_t dns_qtype;
    uint16_t dns_qclass;
};

struct dns_answer {
    uint16_t dns_atype;
    uint16_t dns_aclass;
    uint16_t dns_ttl;
    std::string data;
};

struct dns {
    struct dns_header h;
    struct dns_query questions[256];
    struct dns_answer answers[256];
};

enum dns_types {
    TYPE_A, // 1
    TYPE_NS, // 2
    TYPE_MD, // 3
    TYPE_MF, // 4
    TYPE_CNAME, // 5
    TYPE_SOA, // 6
    TYPE_MB, // 7
    TYPE_MG, // 8
    TYPE_MR, // 9
    TYPE_NULL, // 10
    TYPE_WKS, // 11
    TYPE_PTR, // 12
    TYPE_HINFO, // 13
    TYPE_MINFO, // 14
    TYPE_MX, // 15
    TYPE_TXT // 16
};

int decode_dns(uint8_t const *pkt, uint32_t const len, dns* dns);

#endif /* LIBPACKET_DECODE_DNS_H */
