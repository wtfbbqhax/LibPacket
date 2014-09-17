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
 * 6/28/12 - SCTP support needs substantial work done to make it robust.
 */ 
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet_private.h"

#include "crc32.h"

struct sctp {
    uint16_t sport;
    uint16_t dport;
    uint32_t vtag;
    uint32_t sum;
};

struct sctp_chunk {
    uint8_t type;
    uint8_t flags;
    uint16_t len;
};

extern struct packet_stats s_stats;

static uint32_t
crc32c(void *_buffer, unsigned len)
{
    uint8_t *buffer = (uint8_t *)_buffer;

    uint32_t crc32 = ~0L;
    uint32_t result;
    uint8_t  byte0, byte1, byte2, byte3;

    for (unsigned i = 0; i < len; i++)
        CRC32C(crc32, buffer[i]);

    result = ~crc32;

    byte0 =  result        & 0xff;
    byte1 = (result >>  8) & 0xff;
    byte2 = (result >> 16) & 0xff;
    byte3 = (result >> 24) & 0xff;

    crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 <<  8) | byte3);
    return crc32;
}

int
decode_sctp(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct sctp *sctp = (struct sctp *)pkt;

    s_stats.sctps_packets++;
    s_stats.sctps_bytes += len;

    if (len < sizeof *sctp)
    {
        s_stats.sctps_tooshort++;
        return -1;
    }

    p->srcport = ntohs(sctp->sport);
    p->dstport = ntohs(sctp->dport);

    p->payload += sizeof *sctp;
    p->paysize -= sizeof *sctp;

    packet_layer_ins(p, pkt, sizeof *sctp, PROTO_SCTP);
    p->transport = packet_layer_current(p);

    uint32_t cks = ntohl(sctp->sum);
    sctp->sum = 0;

    if (crc32c(sctp, len) != cks)
    {
        s_stats.sctps_badsum++;
        return -1;
    }

    return 0;
}
