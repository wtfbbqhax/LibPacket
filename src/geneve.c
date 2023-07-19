// https://datatracker.ietf.org/doc/html/rfc8926

#include <stdint.h>
#include <stdbool.h>

#include "packet_private.h"
#include "eth.h"

extern struct packet_stats s_stats;

#define ETHERTYPE_ETH 0x6558

struct geneve_header {
    uint8_t opt_len;
    uint8_t flags;
    uint16_t proto;
    uint32_t vni;
} __attribute__((packed));

#define GENEVE_VERSION(optlen) (((optlen) & 0xC0) >> 6)
#define GENEVE_OPTLEN(optlen)  (((optlen) & 0x3F) * 4)

#define IS_CONTROL_PACKET(flags)    (((flags) & 0x80) >> 7)
#define HAS_CRITICAL_OPTIONS(flags) (((flags) & 0x40) >> 6)
#define FLAGS_RESERVED(flags)        ((flags) & 0x3F)

#define VNI(vni)            (((vni) & 0xFFFFFF00) >> 8)
#define VNI_RESERVED(vni)    ((vni) & 0x000000FF)


static bool inline
_is_valid(struct geneve_header *hdr)
{
    if (GENEVE_VERSION(hdr->opt_len) != 0)
        return false;

    if (FLAGS_RESERVED(hdr->flags) != 0)
        return false;

    if (VNI_RESERVED(hdr->vni) != 0)
        return false;

    return true;
}

int
decode_geneve(const uint8_t *pkt, unsigned len, Packet* packet)
{
    struct geneve_header *hdr = (struct geneve_header*)pkt;

    if (len < sizeof(*hdr))
        return -1;

    unsigned hlen = GENEVE_OPTLEN(hdr->opt_len) + sizeof(*hdr);
    if (len < hlen)
        return -1;

    s_stats.geneve_packets++;

    packet->payload += hlen;
    packet->paysize -= hlen;
    packet_layer_ins(packet, pkt, hlen, PROTO_GENEVE);

    uint16_t proto = ntohs(hdr->proto);
    if (proto == ETHERTYPE_ETH)
        return decode_dlt_eth(pkt + hlen, len - hlen, packet);

    return bind_eth(proto, pkt + hlen, len - hlen, packet);
}
