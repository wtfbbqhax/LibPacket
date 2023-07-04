// Packet flow keying
// Victor Roemer (wtfbbqhax), <victor@badsec.org>.
#include <stdint.h>

#include <packet.h>

#define FNV_PRIME_32  16777619
#define FNV_OFFSET_32 2166136261

static inline
uint32_t fnv1a(uint32_t data_byte, uint32_t hash)
{
    return (data_byte ^ hash) * FNV_PRIME_32;
}

unsigned
packet_flow_key(const uint8_t *data, const size_t len)
{
    Packet packet = {};
    packet_clear(&packet);
    packet_decode(&packet, data, len);

    struct ipaddr src = packet_srcaddr(&packet);
    struct ipaddr dst = packet_dstaddr(&packet);
    struct ipaddr *a = &src;
    struct ipaddr *b = &dst;
    uint16_t sport = packet_srcport(&packet);
    uint16_t dport = packet_dstport(&packet);
    uint8_t proto = packet_protocol(&packet);

    // Note: srcport/dstport are shared with icmp type/code respectively.
    if (proto == IPPROTO_ICMP)
    {
        // ICMP ECHO and ICMP ECHO RESPONSE should be keyed to the same Snort
        // instance.
        if (sport == 0)
        {
            sport = 8;
        }
    }

    // bi-directional keying, treating ip address as most significant bit(s).
    if (ip_compare(&src, &dst) == IP_LESSER)
    {
        a = &dst;
        b = &src;

        // never flip the type and code
        if (proto != IPPROTO_ICMP)
        {
            dport = packet_srcport(&packet);
            sport = packet_dstport(&packet);
        }
    }

    uint32_t hash = FNV_OFFSET_32;
    hash = fnv1a(a->addr8[0], hash); hash = fnv1a(a->addr8[1], hash);
    hash = fnv1a(a->addr8[2], hash); hash = fnv1a(a->addr8[3], hash);
    hash = fnv1a(a->addr8[4], hash); hash = fnv1a(a->addr8[5], hash);
    hash = fnv1a(a->addr8[6], hash); hash = fnv1a(a->addr8[7], hash);
    hash = fnv1a(a->addr8[8], hash); hash = fnv1a(a->addr8[9], hash);
    hash = fnv1a(a->addr8[10], hash); hash = fnv1a(a->addr8[11], hash);
    hash = fnv1a(a->addr8[12], hash); hash = fnv1a(a->addr8[13], hash);
    hash = fnv1a(a->addr8[14], hash); hash = fnv1a(a->addr8[15], hash);

    hash = fnv1a(b->addr8[0], hash); hash = fnv1a(b->addr8[1], hash);
    hash = fnv1a(b->addr8[2], hash); hash = fnv1a(b->addr8[3], hash);
    hash = fnv1a(b->addr8[4], hash); hash = fnv1a(b->addr8[5], hash);
    hash = fnv1a(b->addr8[6], hash); hash = fnv1a(b->addr8[7], hash);
    hash = fnv1a(b->addr8[8], hash); hash = fnv1a(b->addr8[9], hash);
    hash = fnv1a(b->addr8[10], hash); hash = fnv1a(b->addr8[11], hash);
    hash = fnv1a(b->addr8[12], hash); hash = fnv1a(b->addr8[13], hash);
    hash = fnv1a(b->addr8[14], hash); hash = fnv1a(b->addr8[15], hash);

    hash = fnv1a(proto, hash);

    hash = fnv1a((uint8_t)(sport >> 8), hash);
    hash = fnv1a((uint8_t)(sport & 0xFF), hash);
    hash = fnv1a((uint8_t)(dport >> 8), hash);
    hash = fnv1a((uint8_t)(dport & 0xFF), hash);

    return hash;
}
