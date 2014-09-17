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

#ifndef PACKET_STATS_H
#define PACKET_STATS_H

/* Protocol decoding stats
 */
struct packet_stats {
    uint32_t total_packets;     /* total packets received */
    uint32_t total_bytes;       /* total bytes received */
    uint32_t total_errors;      /* bad packet received */

    uint32_t mplss_packets;     /* mpls packets */
    uint32_t mplss_bytes;       /* mpls bytes */
    uint32_t mplss_tooshort;    /* packet too short */

    uint32_t pppoes_packets;    /* pppoe packets */
    uint32_t pppoes_bytes;      /* pppoe bytes */
    uint32_t pppoes_tooshort;   /* packet too short */

    uint32_t ppps_packets;      /* ppp packets */
    uint32_t ppps_bytes;        /* ppp bytes */
    uint32_t ppps_tooshort;     /* packet too short */

    uint32_t ipxs_packets;      /* total number of ipx packets */
    uint32_t ipxs_bytes;        /* total number of ipx bytes */
    uint32_t ipxs_badsum;       /* checksum errors */
    uint32_t ipxs_tooshort;     /* packet too short */

    uint32_t ips_packets;       /* total number of ip packets */
    uint32_t ips_bytes;         /* total number of ip bytes */
    uint32_t ips_badsum;        /* checksum errors */
    uint32_t ips_tooshort;      /* packet too short */
    uint32_t ips_toosmall;      /* not enough data */ // XXX UNUSED
    uint32_t ips_badhlen;       /* ip hlen < data size */ // XXX UNUSED
    uint32_t ips_badlen;        /* ip len < ip hlen */ // XXX UNUSED
    uint32_t ips_fragments;     /* fragments received */

    uint32_t ip6s_packets;       /* total number of ip packets */
    uint32_t ip6s_bytes;         /* total number of ip bytes */
    uint32_t ip6s_ext;           /* hop by hop headers */
    uint32_t ip6s_rte;           /* routing headers */
    uint32_t ip6s_tooshort;      /* packet too short */
    uint32_t ip6s_toosmall;      /* not enough data */ // XXX UNUSED
    uint32_t ip6s_badlen;        /* ip len < ip hlen */ // XXX UNUSED
    uint32_t ip6s_fragments;     /* fragments received */

    uint32_t tcps_packets;      /* total tcp packets */
    uint32_t tcps_bytes;        /* total tcp bytes */
    uint32_t tcps_badsum;       /* checksum errors */
    uint32_t tcps_badoff;       /* bad offset */ // XXX UNUSED
    uint32_t tcps_tooshort;     /* not enough data */

    uint32_t udps_packets;      /* total udp packets */
    uint32_t udps_bytes;        /* total udp bytes */
    uint32_t udps_badsum;       /* checksum errors */
    uint32_t udps_nosum;        /* no checksum */
    uint32_t udps_tooshort;     /* not enough data */

    uint32_t icmps_packets;     /* total icmp packets */
    uint32_t icmps_bytes;       /* total icmp bytes */
    uint32_t icmps_badsum;      /* checksum errors */
    uint32_t icmps_badtype;     /* bad icmp code */
    uint32_t icmps_badcode;     /* bad icmp type */
    uint32_t icmps_tooshort;    /* not enough data */

    uint32_t sctps_packets;     /* total sctp packets */
    uint32_t sctps_bytes;       /* total sctp bytes */
    uint32_t sctps_badsum;      /* checksum errors */
    uint32_t sctps_badtype;     /* bad chunk type */ // XXX UNUSED 
    uint32_t sctps_tooshort;    /* not enough data */
};

#endif /* PACKET_STATS_H */
