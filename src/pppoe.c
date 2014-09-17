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
#include "ppp.h"

/* struct pppoe
 * {
 *     int pppoe_ver:4;
 *     int pppoe_type:4;
 *     uint8_t pppoe_code;
 *     uint16_t pppoe_sid;
 *     uint16_t pppoe_len;
 * };
 */
#define PPPOE_SIZE 6

extern struct packet_stats s_stats;

int
decode_pppoe(Packet *packet, const uint8_t *pkt, unsigned len)
{
    s_stats.pppoes_packets++;
    s_stats.pppoes_bytes+=len;

    if (len < PPPOE_SIZE)
    {
        s_stats.pppoes_tooshort++;
        return -1;
    }

    packet->payload += PPPOE_SIZE;
    packet->paysize -= PPPOE_SIZE;

    packet_layer_ins(packet, pkt, PPPOE_SIZE, PROTO_PPPOE);

    return decode_ppp(packet, pkt + PPPOE_SIZE, len - PPPOE_SIZE);
}

