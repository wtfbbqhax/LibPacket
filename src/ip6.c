/* Copyright (c) 2010-2012, Victor J. Roemer. All Rights Reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <config.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef OPENBSD
# define IPPROTO_SCTP 132
# include <netinet/in.h>
# include <netinet/in_systm.h>
#endif

#define __FAVOR_BSD
#include <arpa/inet.h>
#include <netinet/ip6.h>

#include "packet_private.h"

#include "ip4.h"
#include "ip6.h"
#include "tcp.h"
#include "udp.h"
#include "sctp.h"

extern struct packet_stats s_stats;

struct ip6_rte
{
    uint8_t ip6r_nxt;
    uint8_t ip6r_len;
    uint8_t ip6r_type;
    uint8_t ip6r_segleft;
    uint32_t ip6r_res;
};

static inline int
bind_ip6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    int ret = -1;

    /* not calling bind_ip because icmp won't be a 
     * valid ip6 protocol */
    switch (p->protocol)
    {
        case IPPROTO_ROUTING:
            ret = decode_ip6_rte(pkt, len, p);
            break;
        case IPPROTO_FRAGMENT:
            ret = decode_ip6_frag(pkt, len, p);
            break;
        case IPPROTO_DSTOPTS:
        case IPPROTO_HOPOPTS:
            ret = decode_ip6_ext(pkt, len, p);
            break;
        case IPPROTO_TCP:
            ret = decode_tcp(pkt, len, p);
            break;
        case IPPROTO_UDP:
            ret = decode_udp(pkt, len, p);
            break;
        case IPPROTO_SCTP:
            ret = decode_sctp(pkt, len, p);
            break;
        case IPPROTO_IPIP:
            ret = decode_ip(pkt, len, p);
            break;
    }

    return ret;
}

/* IPv6 Routing Header
 *
 */
int
decode_ip6_rte(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct ip6_rte *rte = (struct ip6_rte *) pkt;
    unsigned rte_len;

    s_stats.ip6s_rte++;

    if (len < sizeof *rte)
        return -1;

    rte_len = rte->ip6r_len * 8 + 8;

    if (len < rte_len)
        return -1;

    p->payload += rte_len; 
    p->paysize -= rte_len;

    packet_layer_ins(p, pkt, rte_len, PROTO_IP6_RTE);

    p->protocol = rte->ip6r_nxt;

    if (rte->ip6r_segleft > 0)
        memcpy(&p->dstaddr, pkt + rte_len - 16, sizeof(p->dstaddr));

    return bind_ip6(pkt + rte_len, len - rte_len, p);
}

/* IPv6 Fragment Header
 *
 */
int
decode_ip6_frag(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct ip6_frag *frag = (struct ip6_frag *) pkt;

    s_stats.ip6s_fragments++;

    if (len < sizeof *frag)
        return -1;

    int ip6_off = ntohs(frag->ip6f_offlg);

    p->offset = (ip6_off & IP6F_OFF_MASK);
    p->mf = (ip6_off & IP6F_MORE_FRAG);
    p->protocol = frag->ip6f_nxt;
    p->id = frag->ip6f_ident;

    p->payload += sizeof *frag; 
    p->paysize -= sizeof *frag;

    packet_layer_ins(p, pkt, sizeof *frag, PROTO_IP6_FRAG);

    if (p->offset || p->mf)
        return 0;

    return bind_ip6(pkt + sizeof(*frag), len - sizeof(*frag), p);
}

/* IPv6 HOP or DST options
 *
 */
int
decode_ip6_ext(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct ip6_ext *ext = (struct ip6_ext *) pkt;
    unsigned ext_len;

    s_stats.ip6s_ext++;

    if (len < sizeof *ext)
        return -1;

    ext_len = (ext->ip6e_len << 3) + 8;

    if (len < ext_len)
        return -1;

    p->paysize -= ntohs(ext_len);
    p->payload += ntohs(ext_len);
    p->protocol = ext->ip6e_nxt;

    p->payload += ext_len; 
    p->paysize -= ext_len;

    packet_layer_ins(p, pkt, ext_len, PROTO_IP6_EXT);

    return bind_ip6(pkt + ext_len, len - ext_len, p);
}

/* IPv6 Header, also decoder entry
 *
 */
int
decode_ip6 (const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;

    s_stats.ip6s_packets++;
    s_stats.ip6s_bytes += len;

    if (len < sizeof *ip6)
    {
        s_stats.ip6s_tooshort++;
        return -1;
    }

    p->version = 6;
    p->protocol = ip6->ip6_nxt;

    // assignment of payload is different here because pay_len is not
    // influenced by potential ethernet padding.
    p->payload += sizeof *ip6;
    p->paysize = ntohs(ip6->ip6_plen);

    packet_layer_ins(p, pkt, sizeof *ip6, PROTO_IP6);

    p->ttl = ip6->ip6_hops;

    memcpy(&p->srcaddr, &ip6->ip6_src, sizeof p->srcaddr);
    memcpy(&p->dstaddr, &ip6->ip6_dst, sizeof p->dstaddr);

    return bind_ip6(pkt + sizeof(*ip6), len - sizeof(*ip6), p);
}
