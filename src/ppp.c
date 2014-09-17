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
#include <stdint.h>

#include "packet_private.h"
#include "ip4.h"
#include "ip6.h"
#include "ipx.h"

#define PPP_IP4 0x0021
#define PPP_IPX 0x002b
#define PPP_IP6 0x0057

extern struct packet_stats s_stats;

static inline int
bind_ppp(uint16_t ppp, Packet *packet, const uint8_t *pkt, unsigned len)
{
    int ret = -1;

    switch(ppp)
    {
        case PPP_IP4:
        ret = decode_ip(pkt, len, packet);
        break;

        case PPP_IP6:
        ret = decode_ip6(pkt, len, packet);
        break;

        case PPP_IPX:
        ret = decode_ipx(packet, pkt, len);
        break;
    };

    return ret;
}

int
decode_ppp(Packet *packet, const uint8_t *pkt, unsigned len)
{
    uint16_t *ppp = (uint16_t *) pkt;

    s_stats.ppps_packets++;
    s_stats.ppps_bytes+=len;

    if (len < sizeof *ppp)
    {
        s_stats.ppps_tooshort++;
        return -1;
    }

    packet->payload += sizeof *ppp;
    packet->paysize -= sizeof *ppp;

    packet_layer_ins(packet, pkt, sizeof *ppp, PROTO_PPP);

    /* same protocols */
    return bind_ppp(ntohs(*ppp), packet, pkt + sizeof(*ppp),
        len - sizeof(*ppp));
}

