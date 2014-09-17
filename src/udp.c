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
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/udp.h>

#include "packet_private.h"

#include "checksum.h"

extern struct packet_stats s_stats;

int
decode_udp(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct udphdr *udp = (struct udphdr *)pkt;

    s_stats.udps_packets++;
    s_stats.udps_bytes+=len;

    if (len < sizeof *udp)
    {
        s_stats.udps_tooshort++;
        return -1;
    }

    packet_layer_ins(p, pkt, sizeof *udp, PROTO_UDP);
    p->transport = packet_layer_current(p);

    p->srcport = ntohs(udp->uh_sport);
    p->dstport = ntohs(udp->uh_dport);

    /* Create the pseudo header before adjusting paysize */
    struct pseudo_hdr pseudo;
    pseudo.srcaddr = p->srcaddr;
    pseudo.dstaddr = p->dstaddr;
    pseudo.zero = 0;
    pseudo.protocol = p->protocol;
    pseudo.len = htons(p->paysize);

    p->payload += sizeof *udp; 
    p->paysize -= sizeof *udp;

    /* UDP checksum is mandatory for ipv6 */
    if (udp->uh_sum == 0 && p->version == 6)
    {
        s_stats.udps_badsum++;
        return -1;
    }
    else if (udp->uh_sum == 0)
        return 0;

    if (checksum((uint16_t *)udp, &pseudo, ntohs(pseudo.len)) != 0)
    {
        s_stats.udps_badsum++;
        return -1;
    }

    return 0;
}
