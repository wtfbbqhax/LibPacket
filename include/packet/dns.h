#ifndef LIBPACKET_DECODE_DNS_H
#define LIBPACKET_DECODE_DNS_H

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

struct dns_label {
    uint8_t *p;
    uint8_t len;
};

struct dns_query {
    //struct dns_label labels[32];
    // Store QTYPE and QCLASS (assuming a structure in Packet to store this information)
    uint16_t dns_qtype;
    uint16_t dns_qclass;
};

struct dns_answer {
    uint16_t dns_atype;
    uint16_t dns_aclass;
    uint16_t dns_ttl;
    uint16_t dns_rdlength;
    uint16_t dns_rdata;
};

struct dns {
    struct dns_header h;
    struct dns_query questions[256];
    struct dns_answer answers[256];
};

int decode_dns(uint8_t const *pkt, uint32_t const len, dns* dns);

#endif /* LIBPACKET_DECODE_DNS_H */
