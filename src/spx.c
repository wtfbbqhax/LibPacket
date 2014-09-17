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

#include <stdint.h>

#include "packet_private.h"

/* spx structure as seen in FreeBSD's netipx/spx.h */
struct spx
{
    uint8_t spx_cc;
    uint8_t spx_dt;
#define SPX_SP 0x80
#define SPX_SA 0x40
#define SPX_OB 0x20
#define SPX_EM 0x10
    uint16_t spx_sid;
    uint16_t spx_did;
    uint16_t spx_seq;
    uint16_t spx_ack;
    uint16_t spx_alo;
};

int
decode_spx(Packet *p, const uint8_t * pkt, const uint32_t len)
{
    struct spx *spx = (struct spx *) pkt;

    if (len < sizeof *spx)
    {
        return -1;
    }

    packet_layer_ins(p, pkt, sizeof *spx, PROTO_SPX);

    p->payload += sizeof *spx;
    p->paysize -= sizeof *spx;

    return 0;
}
