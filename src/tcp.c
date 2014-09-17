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

#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include "packet_private.h"

#include "checksum.h"

extern struct packet_stats s_stats;

/* Table that maps ordinal (option type) to option length. 
 * Refer to link for more information.
 * http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml
 *
 * Note that we only bother ourselves with the first 8 option types.
 * In the future, I may build a full table 0-254.
 *
 *  0 - No length (EOL, NOP)
 * >0 - Fixed length
 * -1 - Variable length
 */
static const int8_t tcpopt_len_tbl[] =
{
     0, 0, 4, 3, 2, -1, 6, 6, 10
};

#define TCPOPT_MAX (sizeof(tcpopt_len_tbl)/sizeof(tcpopt_len_tbl[0]))

/* Some sort of state machine for parsing tcp options. */
/* This was allot harder than it should have been. */
static inline void 
decode_tcp_options(Packet *p, const uint8_t *start, const unsigned len)
{
    if (len > MAX_TCPOPTLEN)
        return;

    const uint8_t *opt_start = start;
    unsigned depth = 0;

    while (opt_start < start + len)
    {
        uint8_t jmp_len, opt_len;

        /* Useless option code detected */
        if (*opt_start >= TCPOPT_MAX)
        {
            if (!((len-depth) > 0))
                return;

            jmp_len = *(opt_start + 1);

            /* skip processing and retrieve next option, abort otherwise */
            if (len < jmp_len)
                goto nxt_tcp_opt;
            else
                return;
        }

        int8_t expected = tcpopt_len_tbl[*opt_start];

        switch (expected)
        {
            /* Variable length option */
            case -1:
                if (!((len-depth) > 0)) return;
                jmp_len = *(opt_start + 1);
                opt_len = jmp_len - 2;
                break;

            /* EOL or NOP */
            case 0:
                jmp_len = 1;
                opt_len = expected;
                break;

            /* Fixed size */
            default:
                if (!((len-depth) > 0)) return;
                jmp_len = *(opt_start + 1);

                /* Validate it is the correct length */
                if (jmp_len != expected) return;
                opt_len = jmp_len - 2;
                break;
        }

        /* Add this option to the tcp opts array */
        p->tcp_option[p->tcpopt_count].type = *opt_start;
        p->tcp_option[p->tcpopt_count].len = opt_len;
        p->tcp_option[p->tcpopt_count].value = opt_len ? (opt_start + 2): NULL;
        p->tcpopt_count++;

nxt_tcp_opt:
        depth += jmp_len;
        opt_start += jmp_len;
    }

    return;
}

int
decode_tcp(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct tcphdr *tcp = (struct tcphdr *)pkt;

    s_stats.tcps_packets++;
    s_stats.tcps_bytes += len;

    if (len < sizeof *tcp)
    {
        s_stats.tcps_tooshort++;
        return -1;
    }

    unsigned hlen = tcp->th_off * 4;
    if (len < hlen)
    {
        s_stats.tcps_tooshort++;
        return -1;
    }

    packet_layer_ins(p, pkt, hlen, PROTO_TCP);
    p->transport = packet_layer_current(p);

    p->srcport = ntohs(tcp->th_sport);
    p->dstport = ntohs(tcp->th_dport);

    /* Create the pseudo header before adjusting paysize */
    struct pseudo_hdr pseudo;
    pseudo.srcaddr = p->srcaddr;
    pseudo.dstaddr = p->dstaddr;
    pseudo.zero = 0;
    pseudo.protocol = p->protocol;
    pseudo.len = htons(p->paysize);

    p->payload += hlen;
    p->paysize -= hlen;

    /* decode tcp options */
    unsigned short optlen = hlen - sizeof *tcp;
    if (optlen)
    {
        decode_tcp_options(p, pkt + hlen - optlen, optlen);
    }

    /* Lastly check the checksum */
    if (checksum((uint16_t *)tcp, &pseudo, ntohs(pseudo.len)) != 0)
    {
        s_stats.tcps_badsum++;
        return -1;
    }

    return 0;
}
