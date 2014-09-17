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
#include <inttypes.h>

#ifdef OPENBSD
# define IPPROTO_SCTP 132
# include <netinet/in.h>
# include <netinet/in_systm.h>
#endif

#define __FAVOR_BSD
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "packet_private.h"

#include "checksum.h"
#include "ip4.h"
#include "ip6.h"
#include "tcp.h"
#include "udp.h"
#include "sctp.h"

extern struct packet_stats s_stats;

static inline int
bind_ip(const uint8_t * pkt, const uint32_t len, Packet *p)
{
    int ret = -1;

    switch (p->protocol)
    {
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
        case IPPROTO_IPV6:
            ret = decode_ip6(pkt, len, p);
            break;
    }

    return ret;
}

int
decode_ip(const uint8_t * pkt, const uint32_t len, Packet *p)
{
    struct ip *ip = (struct ip *) pkt;
    unsigned hlen = ip->ip_hl * 4;
    unsigned pay_len = ntohs((uint16_t) ip->ip_len) - hlen;

    s_stats.ips_packets++;
    s_stats.ips_bytes += len;

    p->version = 4;

    if (len < hlen || len < pay_len)
    {
        s_stats.ips_tooshort++;
        return -1;
    }

    packet_layer_ins(p, pkt, hlen, PROTO_IP4);

    p->offset = ntohs(ip->ip_off);

    p->df = (uint8_t) ((p->offset & 0x4000) >> 14);
    p->mf = (uint8_t) ((p->offset & 0x2000) >> 13);

    p->offset &= IP_OFFMASK;

    p->payload += hlen;
    p->paysize = pay_len;

    p->id = ip->ip_id;
    p->tos = ip->ip_tos;
    p->ttl = ip->ip_ttl;

    p->srcaddr.addr32[0] = ip->ip_src.s_addr;
    p->dstaddr.addr32[0] = ip->ip_dst.s_addr;

    p->protocol = ip->ip_p;

    if (checksum((uint16_t *)ip, NULL, hlen) != 0)
    {
        s_stats.ips_badsum++;
        return -1;
    }

    if (p->offset || p->mf)
    {
        s_stats.ips_fragments++;
        return 0;
    }

    return bind_ip(pkt + hlen, len - hlen, p);
}
