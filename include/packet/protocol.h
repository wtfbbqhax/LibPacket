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

/* NOTE: packet/packet.h defines type Packet, thus this file relies
 * on it.  */

#ifndef PACKET_PROTOCOL_H
#define PACKET_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _PacketLayer Protocol;

typedef enum
{
    PROTO_ETH,
    PROTO_PPP,
    PROTO_VLAN,
    PROTO_MPLS,
    PROTO_PPPOE,
    PROTO_IPX,
    PROTO_SPX,
    PROTO_IP4,
    PROTO_IP6,
    PROTO_IP6_RTE,
    PROTO_IP6_FRAG,
    PROTO_IP6_EXT, /* DST OPTS and HBH */
    PROTO_GRE,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_SCTP,
    PROTO_ICMP,
    PROTO_ICMP6,
    PROTO_MAX
} PROTOCOL;

#ifdef __cplusplus
};
#endif

#endif /* PACKET_PROTOCOL_H */
