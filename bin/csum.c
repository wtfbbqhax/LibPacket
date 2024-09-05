/*
 * Copyright (c) Victor Roemer, 2013. All rights reserved.
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * ip_checksum() is a modified version of that in libdnet.
 */

#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

int ip_cksum_add ( const void *buf, size_t len, int cksum )
{
    uint16_t *sp = (uint16_t *)buf;
    int sn = len / 2;
    int n = (sn + 15) / 16;

    switch ( sn % 16 ) {
        case 0: do {    cksum += *sp++;
        case 15:        cksum += *sp++;
        case 14:        cksum += *sp++;
        case 13:        cksum += *sp++;
        case 12:        cksum += *sp++;
        case 11:        cksum += *sp++;
        case 10:        cksum += *sp++;
        case 9:         cksum += *sp++;
        case 8:         cksum += *sp++;
        case 7:         cksum += *sp++;
        case 6:         cksum += *sp++;
        case 5:         cksum += *sp++;
        case 4:         cksum += *sp++;
        case 3:         cksum += *sp++;
        case 2:         cksum += *sp++;
        case 1:         cksum += *sp++;
        } while ( --n > 0 );
    }
    if ( len & 1 )
        cksum += htons(*(uint8_t *)sp << 8);

    return cksum;
}

#define  ip_cksum_carry(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

void ip_checksum(void *buf, size_t len)
{
    struct ip *ip;
    int hl, off, sum;

    ip = (struct ip *)buf;
    hl = ip->ip_hl << 2;
    ip->ip_sum = 0;
    sum = ip_cksum_add(ip, hl, 0);
    ip->ip_sum = ip_cksum_carry(sum);

    off = htons(ip->ip_off);

    if ((off & IP_OFFMASK) != 0 || (off & IP_MF) != 0)
        return;

    len -= hl;

    if ( ip->ip_p == IPPROTO_TCP )
    {
        struct tcphdr *tcp = (struct tcphdr *)((uint8_t *)ip + hl);

        tcp->th_sum = 0;
        sum = ip_cksum_add(tcp, len, 0) + htons(ip->ip_p + len);
        sum = ip_cksum_add(&ip->ip_src, 8, sum);
        tcp->th_sum = ip_cksum_carry(sum);
    }
    else if ( ip->ip_p == IPPROTO_IPIP )
    {
        ip_checksum(((uint8_t *)ip + hl), len);
    }
}
