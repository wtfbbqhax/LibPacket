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
/* XXX
 * 6/28/12 - IPX support needs substantial work done to make it robust.
 */ 
#include <config.h>

#include <stdint.h>

#include "packet_private.h"
#include "spx.h"

struct ipx
{
    uint16_t ipx_cks;           // unimplemented always ffff
    uint16_t ipx_len;
    uint8_t ipx_ttl;
    uint8_t ipx_type;
    /* Network number 0x00000000 means current network.
     * Network number 0xffffffff is broadcast address.  */
    uint8_t ipx_dst_net[4];
    uint8_t ipx_dst_node[6];    // mac address
    uint16_t ipx_dst_socket;    // Dest Port :|
    uint8_t ipx_src_net[4];
    uint8_t ipx_src_node[6];
    uint16_t ipx_src_socket;
};

#define IPXPROTO_UNKWN      0    
#define IPXPROTO_RI         1    
#define IPXPROTO_PXP        4
#define IPXPROTO_SPX        5
#define IPXPROTO_NCP        17
#define IPXPROTO_NETBIOS    20 
#define IPXPROTO_RAW        255 

extern struct packet_stats s_stats;

static inline int
bind_ipx(Packet *p, const uint8_t * pkt, const uint32_t len)
{
    int ret = -1;

    switch (p->protocol)
    {
        case IPXPROTO_SPX:
        ret = decode_spx(p, pkt, len);
        break;

        default:
        ret = 0;
    }

    return ret;
}

int
decode_ipx(Packet *p, const uint8_t * pkt, const uint32_t len)
{
    struct ipx *ipx = (struct ipx *) pkt;

    s_stats.ipxs_packets++;
    s_stats.ipxs_bytes+=len;

    if (len < sizeof *ipx)
    {
        s_stats.ipxs_tooshort++;
        return -1;
    }

    packet_layer_ins(p, pkt, sizeof *ipx, PROTO_IPX);

    p->payload += sizeof *ipx;
    p->paysize -= sizeof *ipx;

    if (ipx->ipx_cks != 0xffff)
    {
        s_stats.ipxs_badsum++;
        return -1;
    }

    /* processing ends here for now, need to implement:
     *      RIP,
     *      SAP,
     *      SPX,
     *      NLSP
     */

    return bind_ipx(p, pkt + sizeof *ipx, len - sizeof *ipx);
}
