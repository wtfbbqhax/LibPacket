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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef OPENBSD
#include <net/if.h>
#include <net/if_arp.h>
#else
#include <net/ethernet.h>
#endif

#include <netinet/if_ether.h>

#ifdef LINUX
#include <netinet/ether.h>
#endif

#include "packet_private.h"
#include "vlan.h"
#include "mpls.h"
#include "pppoe.h"
#include "ipx.h"
#include "ip4.h"
#include "ip6.h"

#ifndef ETHERTYPE_MPLS
# define ETHERTYPE_MPLS 0x8847
#endif

#ifndef ETHERTYPE_PPPOE
# define ETHERTYPE_PPPOE 0x8864
#endif

#ifndef ETHERTYPE_IPX
# define ETHERTYPE_IPX 0x8137
#endif

int
bind_eth(int proto, const unsigned char *pkt, unsigned len,
    Packet *packet)
{
    int ret = -1;

    switch (proto)
    {
        case ETHERTYPE_IP:
            ret = decode_ip(pkt, len, packet);
            break;
        case ETHERTYPE_IPV6:
            ret = decode_ip6(pkt, len, packet);
            break;
        case ETHERTYPE_VLAN:
            ret = decode_vlan(packet, pkt, len);
            break;
        case ETHERTYPE_MPLS:
            ret = decode_mpls(packet, pkt, len);
            break;
        case ETHERTYPE_PPPOE:
            ret = decode_pppoe(packet, pkt, len);
            break;
        case ETHERTYPE_IPX:
            ret = decode_ipx(packet, pkt, len);
            break;
    }

    return ret;
}

int
decode_dlt_eth(const unsigned char *pkt, unsigned len, Packet *packet)
{
    struct ether_header *eth = (struct ether_header *)pkt;

    if (len < sizeof *eth)
        return -1;

    packet->payload += sizeof *eth;
    packet->paysize -= sizeof *eth;

    packet_layer_ins(packet, pkt, sizeof *eth, PROTO_ETH);

    return bind_eth(ntohs(eth->ether_type), pkt + sizeof(*eth),
        len - sizeof(*eth), packet);
}

