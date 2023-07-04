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

/* TODO: When processing errors like "destination unreachable", "network
 * unreachable", etc., we should attempt to extract the partial packet stub
 * in the icmp payload.
 *
 * The goal is to send these router messages to the Snort instance that would
 * have processed packet which the message pertains too. Even though Snort does
 * not process ICMP messages to terminate flows (this would be a huge evasion
 * loophole), these messages are extremely interesting.
 *
 * NOTICE: This is a level of security focused packet steering potentially
 * worthy of patent or copyright.
 */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/icmp6.h>

#include "packet_private.h"

#include "checksum.h"


struct icmp6
{
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    union
    {
        uint32_t data32[1];
        uint16_t data16[2];
        uint8_t  data8[4];
    };
};


#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129
#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REPORT         131
#define MLD_LISTENER_REDUCTION      132
#define ICMPV6_EXT_ECHO_REQUEST	    160
#define ICMPV6_EXT_ECHO_REPLY	    161

#define ICMP6_DST_UNREACH_NOROUTE     0 /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN       1 /* communication with destination */
                                        /* administratively prohibited */
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2 /* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR        3 /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT      4 /* bad port */

#define ICMP6_TIME_EXCEED_TRANSIT     0 /* Hop Limit == 0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 /* Reassembly time out */

#define ICMP6_PARAMPROB_HEADER        0 /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER    1 /* unrecognized Next Header */
#define ICMP6_PARAMPROB_OPTION        2 /* unrecognized IPv6 option */

#


extern struct packet_stats s_stats;

int
decode_icmp6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    struct icmp6 *icmp = (struct icmp6 *)pkt;

    s_stats.icmps_packets++;
    s_stats.icmps_bytes+=len;

    if (len < sizeof *icmp)
    {
        s_stats.icmps_tooshort++;
        return -1;
    }

    packet_layer_ins(p, pkt, sizeof *icmp, PROTO_ICMP6);
    p->transport = packet_layer_current(p);

    p->srcport = icmp->type;
    p->dstport = icmp->code;

    /* Create the pseudo header before adjusting paysize */
    struct pseudo_hdr pseudo;
    pseudo.srcaddr = p->srcaddr;
    pseudo.dstaddr = p->dstaddr;
    pseudo.zero = 0;
    pseudo.protocol = p->protocol;
    pseudo.len = htons(p->paysize);

    p->payload += sizeof *icmp; 
    p->paysize -= sizeof *icmp;

    if (checksum((uint16_t *)icmp, &pseudo, ntohs(pseudo.len)) != 0)
    {
        s_stats.icmps_badsum++;
        //return -1;
    }

    return 0;
}
