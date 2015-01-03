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
#ifndef PACKET_PRIVATE_H
#define PACKET_PRIVATE_H

#ifdef DEBUG
#define inline
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>

#include <netinet/tcp.h>

#include "packet.h"
#include "checksum.h"

struct _PacketLayer
{
    PROTOCOL protocol;
    unsigned size;
    const uint8_t *start;
};

#ifndef MAX_LAYERS
# define MAX_LAYERS 32
#endif

#warning "MAX_TCPOPTLEN value 32 is only a guessed value to fix compilation"
#define MAX_TCPOPTLEN 32

struct _Packet
{
    unsigned version;
    struct ipaddr srcaddr;
    struct ipaddr dstaddr;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t protocol;
    bool mf, df;
    uint16_t offset;
    uint32_t id;
    uint8_t ttl;
    uint8_t tos;
    uint16_t mss;
    uint8_t wscale;
    unsigned paysize;
    const uint8_t *payload;

    /* Alt payload is set outside of libpacket */
    unsigned alt_paysize;
    uint8_t *alt_payload;

    Protocol *transport;
    unsigned layer_count;
    unsigned tcpopt_count;

    /* Start of some static lists */
    Protocol layer[MAX_LAYERS];
    Option tcp_option[MAX_TCPOPTLEN];
};
#define PKT_ZERO_LEN offsetof(Packet, tcpopt_count)

int packet_layer_ins(Packet *packet, const uint8_t *start,
    unsigned size, PROTOCOL proto);

int packet_layer_rem(Packet *packet);

Protocol * packet_layer_current(Packet *packet);

/* Inline packet helpers */
static inline bool
validate_transport_protocol(Packet *packet, PROTOCOL protocol)
{
    if (packet->transport == NULL)
        return false;

    if (packet->transport->protocol != protocol)
        return false;

    return true;
}

#endif /* PACKET_PRIVATE_H */
