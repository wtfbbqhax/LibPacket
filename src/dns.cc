//
// libpacket/src/dns.c: DNS protocol decoder
// Victor Roemer (wtfbbqhax), <victor@badsec.org>.
//
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h> // dns_print_data

#include <arpa/inet.h>

#include <iostream>
#include <string>

#include "packet_private.h"
#include "packet/dns.h"

#define IS_SET(test, bits) (((test) & (bits)) == (bits))

struct dns_stats s_dns_stats;

uint32_t constexpr MINIMUM_DNS_HEADER_SIZE = (sizeof(dns_header));

//static inline void
extern "C" void
decode_label(uint8_t const* raw, uint8_t const* ptr, std::string& _label)
{
    uint8_t off;
    uint8_t label_len;

    if (ptr[0] == 0) {
        return;
    }

    scan_again:
    if (IS_SET(ptr[0], 0xC0)) {
        off = ptr[1];
        ptr = &raw[off];
    }

    label_len = ptr[0];
    ptr++;

    _label.append(reinterpret_cast<char const*>(ptr), label_len);
    _label.append(".");
    ptr += label_len;

    if (ptr[0] != 0) {
        goto scan_again;
    }
}

// Function to decode the DNS protocol
extern "C" int
decode_dns(uint8_t const * pkt, uint32_t const len, dns* dns)
{
    if (len < MINIMUM_DNS_HEADER_SIZE) {
        s_dns_stats.dns_tooshort++;
        return -1;
    }

    struct dns_header const* raw =
            (struct dns_header const*)pkt;

    dns->h.id = ntohs(raw->id);
    dns->h.flags = ntohs(raw->flags);
    dns->h.qdcount = ntohs(raw->qdcount);
    dns->h.ancount = ntohs(raw->ancount);
    dns->h.nscount = ntohs(raw->nscount);
    dns->h.arcount = ntohs(raw->arcount);

    uint8_t const * ptr = pkt + MINIMUM_DNS_HEADER_SIZE;
    uint32_t remaining_len = len - MINIMUM_DNS_HEADER_SIZE;

    if (dns->h.qdcount >= 256)
    {
        s_dns_stats.dns_too_many_queries++;
        return 0;
    }

    // Parsing Question Section
    for (int i = 0; i < dns->h.qdcount; i++)
    {
        struct dns_query* q = &dns->questions[i];

        // Parse QNAME
        while (remaining_len > 0 && *ptr != 0)
        {
            uint8_t label_len = *ptr;
            ptr++;
            remaining_len--;

            if (remaining_len < label_len)
            {
                s_dns_stats.dns_tooshort++;
                return -1;
            }

            q->label.append(reinterpret_cast<char const*>(ptr), label_len);
            q->label.append(".");

            ptr += label_len;
            remaining_len -= label_len;
        }

        // Null byte at the end of QNAME
        if (remaining_len == 0)
        {
            s_dns_stats.dns_tooshort++;
            return -1;
        }
        ptr++;
        remaining_len--;

        // Parse QTYPE and QCLASS
        if (remaining_len < 4) {
            s_dns_stats.dns_tooshort++;
            return -1;
        }
        uint16_t qtype = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        remaining_len -= 2;
        uint16_t qclass = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        remaining_len -= 2;

        // Store QTYPE and QCLASS (assuming a structure in Packet to store this information)
        q->dns_qtype = qtype;
        q->dns_qclass = qclass;
    }

    if (dns->h.ancount >= 256) {
        s_dns_stats.dns_too_many_answers++;
        return 0;
    }

    for (int i = 0; i < dns->h.ancount; i++)
    {
        struct dns_answer *a = &dns->answers[i];

        // Parse NAME (pointer or label)
        if (remaining_len < 2) {
            s_dns_stats.dns_tooshort++;
            return -1;
        }

        // The "name" appears to be a  partial label, but I can't find that
        // documented in rfc1035, more testing is needed.
        std::string name;
        if (IS_SET(ptr[0], 0xC0)) {
            uint8_t off = ptr[1];
            uint8_t const* label = &pkt[off];
            uint8_t label_len = *label;
            while(label[0] != 0)
            {
              label++;
              name.append(reinterpret_cast<char const*>(label), label_len);
              name.append(".");
              label += label_len;
            }
        }

        ptr += 2;
        remaining_len -= 2;

        // Parse TYPE, CLASS, TTL, RDLENGTH
        if (remaining_len < 10) {
            s_dns_stats.dns_tooshort++;
            return -1;
        }

        uint16_t atype = ntohs(*(uint16_t *)ptr);
        assert(sizeof atype == 2);
        ptr += sizeof atype;
        remaining_len -= sizeof atype;

        uint16_t aclass = ntohs(*(uint16_t *)ptr);
        assert(sizeof aclass == 2);
        ptr += sizeof aclass;
        remaining_len -= sizeof aclass;

        uint32_t ttl = ntohl(*(uint32_t *)ptr);
        assert(sizeof ttl == 4);
        ptr += sizeof ttl;
        remaining_len -= sizeof ttl;

        uint16_t rdlength = ntohs(*(uint16_t *)ptr);
        assert(sizeof atype == 2);
        ptr += sizeof rdlength;
        remaining_len -= sizeof rdlength;

        // Parse RDATA
        if (remaining_len < rdlength) {
            s_dns_stats.dns_tooshort++;
            return -1;
        }

        // Store answer information (assuming a structure in Packet to store
        // this information)
        a->dns_atype = atype;
        a->dns_aclass = aclass;
        a->dns_ttl = ttl;

        if (atype == 1 || atype == 28)
        {
            a->data.append(reinterpret_cast<char const*>(ptr), rdlength);
        }
        else
        {
            // Parse rdata
            decode_label(pkt, ptr, a->data);
        }

        //const uint8_t *rdata = ptr;
        ptr += rdlength;
        remaining_len -= rdlength;
    }

    return 0;
}

