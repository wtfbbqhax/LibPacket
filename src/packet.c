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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#define __FAVOR_BSD
#include <netinet/tcp.h>

#include "packet_private.h"

#include "raw.h"
#include "eth.h"
#include "ip4.h"
#include "ip6.h"
#include "tcp.h"
#include "udp.h"
#include "sctp.h"

struct packet_stats s_stats;

static int
(*decode_dlt)(const uint8_t *pkt, unsigned len, Packet *packet) = &decode_dlt_eth;

Packet *
packet_create()
{
    Packet *packet = malloc(sizeof *packet);
    if (packet == NULL)
        return NULL;

    memset(packet, 0, PKT_ZERO_LEN);
    return packet;
}

void
packet_destroy(Packet *packet)
{
    if (packet == NULL)
        return;

    if (packet->alt_payload)
        free(packet->alt_payload);

    free(packet);
}

int
packet_set_datalink(unsigned datalink)
{
    switch(datalink)
    {
        case DLT_EN10MB:
        decode_dlt = &decode_dlt_eth;
        return 0;

        case DLT_RAW:
        decode_dlt = &decode_dlt_raw;
        return 0;
    }

    return -1;
}

int
packet_decode(Packet *packet, const uint8_t *pkt, unsigned len)
{
    if (packet == NULL || pkt == NULL || len == 0)
        return -1;

    s_stats.total_packets++;
    s_stats.total_bytes += len;

    packet->payload = pkt;
    packet->paysize = len;

    int ret = decode_dlt(pkt, len, packet);

    if (ret) s_stats.total_errors ++;

    return ret;
}

#ifdef HAVE_PCAP_H
int
packet_decode_pcap(Packet *packet, const uint8_t *pkt,
    const struct pcap_pkthdr *pkthdr)
{
    if (pkthdr == NULL)
        return -1;

    return packet_decode(packet, pkt, pkthdr->caplen);
}
#endif /* HAVE_PCAP_H */

/*
 * Library routines
 */
static const char packet_version_string[] =
    PACKAGE " version " PACKAGE_VERSION;

const char *
packet_lib_version(void)
{
    return packet_version_string;
}

void
packet_stats(const struct packet_stats **ps)
{
    *ps = &s_stats;
}

/*
 * Packet Layer Accessors/Iterators
 */
inline Protocol *packet_proto_first(Packet *packet, unsigned *iterator)
{
    *iterator = 0;

    if (packet->layer_count > 0)
        return &packet->layer[0];

    return NULL;
}

inline Protocol *packet_proto_next(Packet *packet, unsigned *iterator)
{
    *iterator = *iterator + 1;

    if (*iterator < packet->layer_count)
        return &packet->layer[*iterator];

    return NULL;
}

inline Protocol *packet_proto_layer(Packet *packet, unsigned layer)
{
    if (layer < packet->layer_count)
        return &packet->layer[layer];

    return NULL;
}

inline unsigned packet_proto_count(Packet *packet)
{
    return packet->layer_count;
}

inline int packet_proto_size(Protocol *proto)
{
    return proto->size;
}

inline const uint8_t *packet_proto_data(Protocol *proto)
{
    return proto->start;
}

inline PROTOCOL packet_proto_proto(Protocol *proto)
{
    return proto->protocol;
}

/* XXX Needs to remain in the same order as PROTOCOL in
 * $(srcdir)/include/packet/protocol.h */
static const char *proto_map[PROTO_MAX] = {
    "eth",
    "ppp",
    "vlan",
    "mpls",
    "pppoe",
    "ipx",
    "spx",
    "ip4",
    "ip6",
    "rte6",
    "frag6",
    "ext6",
    "gre",
    "tcp",
    "udp",
    "sctp",
    "icmp",
    "icmp6"
};

#define ENUM2STR(num, map) \
    ((num < sizeof(map)/sizeof(map[0])) ? map[num] : "undefined")

inline const char *packet_proto_name(Protocol *proto)
{
    return ENUM2STR(proto->protocol, proto_map);
}

/* IP Protocol Accessors */
inline int packet_version(Packet *packet)
{
    return packet->version;
}

inline struct ipaddr packet_srcaddr(Packet *packet)
{
    return packet->srcaddr;
}

inline struct ipaddr packet_dstaddr(Packet *packet)
{
    return packet->dstaddr;
}

inline bool packet_is_fragment(Packet *packet)
{
    return packet->offset || packet->mf;
}

inline bool packet_frag_mf(Packet *packet)
{
    return packet->mf;
}

inline bool packet_frag_df(Packet *packet)
{
    return packet->df;
}

inline uint16_t packet_frag_offset(Packet *packet)
{
    return packet->offset;
}

inline uint8_t packet_protocol(Packet *packet)
{
    return packet->protocol;
}

inline uint32_t packet_id(Packet *packet)
{
    return packet->id;
}

inline uint8_t packet_ttl(Packet *packet)
{
    return packet->ttl;
}

inline uint8_t packet_tos(Packet *packet)
{
    return packet->tos;
}

/* Transport Protocol Accessors */
inline uint16_t packet_srcport(Packet *packet)
{
    return packet->srcport;
}

inline uint16_t packet_dstport(Packet *packet)
{
    return packet->dstport;
}

/* TCP Accessors */
inline uint16_t packet_mss(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    // TODO implement me
    return 0;
}

inline uint16_t packet_win(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    return ntohs(((struct tcphdr *)(packet->transport->start))->th_win);
}

inline uint16_t packet_winscale(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    // TODO implement me
    return 0;
}

inline uint32_t packet_seq(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    return ntohl(((struct tcphdr *)(packet->transport->start))->th_seq);
}

inline uint32_t packet_ack(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    return ntohl(((struct tcphdr *)(packet->transport->start))->th_ack);
}

/* TCP Flags Accessors */
inline int packet_tcpflags(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return 0;

    return ((struct tcphdr *)packet->transport->start)->th_flags;
}

inline bool packet_tcp_fin(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_FIN;
}

inline bool packet_tcp_syn(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_SYN;
}

inline bool packet_tcp_rst(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_RST;
}

inline bool packet_tcp_push(Packet *packet)
{
    if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_PUSH;
}

inline bool packet_tcp_ack(Packet *packet)
{
   if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_ACK;
}

inline bool packet_tcp_urg(Packet *packet)
{
   if (!validate_transport_protocol(packet, PROTO_TCP))
        return false;

    return ((struct tcphdr *)packet->transport->start)->th_flags & TH_URG;
}

inline void packet_set_payload(Packet *packet,
    void *_payload, uint32_t paysize)
{
    uint8_t *payload = (uint8_t *)_payload;
    packet->alt_payload = payload;
    packet->alt_paysize = paysize;
    return;
}

inline bool packet_has_alt_payload(Packet *packet)
{
    /* should not be necessary to check both of these values */
    return (packet->alt_payload || packet->alt_paysize);
}

/* just return the raw values for this packet
 * this could provide a subtle performance increase if used correctly */
inline uint32_t packet_raw_paysize(Packet *packet)
{
    return packet->paysize;
}

inline const uint8_t *packet_raw_payload(Packet *packet)
{
    return packet->payload;
}

/* these functions will return the alternate payload if it exists
 * otherwise they return the raw payload */
inline uint32_t packet_paysize(Packet *packet)
{
    return (packet->alt_paysize ?  packet->alt_paysize : packet->paysize);
}

inline const uint8_t *packet_payload(Packet *packet)
{
    return (packet->alt_payload ?  packet->alt_payload : packet->payload);
}
