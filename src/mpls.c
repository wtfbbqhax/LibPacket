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
/*
 * TODO implement heuristics with reserved mpls labels
 *
 *
 */
#include <stdint.h>

#include "packet_private.h"
#include "mpls.h"
#include "ip4.h"
#include "ip6.h"

extern struct packet_stats s_stats;

static inline int
bind_mpls(Packet *packet, unsigned char nib, bool bos,
    const uint8_t *pkt, unsigned len)
{
    if (!bos)
        decode_mpls(packet, pkt, len);

    switch (nib) {
        case 4:
            decode_ip(pkt, len, packet);
            break;
        case 6:
            decode_ip6(pkt, len, packet);
            break;
    }
    return 0;
}

int
decode_mpls(Packet *packet, const uint8_t *pkt, unsigned len)
{
    uint32_t *mpls = (uint32_t *)pkt;

    s_stats.mplss_packets++;
    s_stats.mplss_bytes+=len;

    if (len < sizeof(*mpls))
    {
        s_stats.mplss_tooshort++;
        return -1;
    }

    uint8_t nibble, bos;

    /* ip version nibble */
    nibble = (char)*(mpls+1) >> 4;
    bos = (*mpls & 0x10000) >> 16;

    packet->payload += sizeof *mpls;
    packet->paysize -= sizeof *mpls;

    packet_layer_ins(packet, pkt, sizeof *mpls, PROTO_MPLS);

    return bind_mpls(packet, nibble, bos, pkt + sizeof(*mpls),
        len - sizeof(*mpls));
}
