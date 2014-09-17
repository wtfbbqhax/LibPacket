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

/*
 * IPv4/IPv6 Address Encapsulation
 */
#include <stdint.h>
#include <netinet/in.h>
#ifndef PACKET_IPADDR_H
#define PACKET_IPADDR_H

struct ipaddr {
    union {
        uint64_t addr64[2];
        uint32_t addr32[4];
        uint16_t addr16[8];
        uint8_t  addr8[16];
    } __ipa_u_;
#define addr64 __ipa_u_.addr64
#define addr32 __ipa_u_.addr32
#define addr16 __ipa_u_.addr16
#define addr8  __ipa_u_.addr8
}; 

typedef enum {
    IP_LESSER = -1,
    IP_EQUAL,
    IP_GREATER,
} IP_CODE;

/* 
 * Compare 2 ip address structures, return whether ip_1
 * is greater than, less than or equal too ip_2.
 */
static inline int
ip_compare(struct ipaddr *ip_1, struct ipaddr *ip_2)
{
    /* Profiling tests show that 32 bit comparisons are 
     * wayyy faster on 32 bit platforms than the 64 bit
     * variants.  */
#ifndef __x86_64__
    if (ip_1->addr32[0] < ip_2->addr32[0])
        return IP_LESSER;
    if (ip_1->addr32[0] > ip_2->addr32[0])
        return IP_GREATER;
    if (ip_1->addr32[1] < ip_2->addr32[1])
        return IP_LESSER;
    if (ip_1->addr32[1] > ip_2->addr32[1])
        return IP_GREATER;
    if (ip_1->addr32[2] < ip_2->addr32[2])
        return IP_LESSER;
    if (ip_1->addr32[2] > ip_2->addr32[2])
        return IP_GREATER;
    if (ip_1->addr32[3] < ip_2->addr32[3])
        return IP_LESSER;
    if (ip_1->addr32[3] > ip_2->addr32[3])
        return IP_GREATER;
#else
    if (ip_1->addr64[0] < ip_2->addr64[0])
        return IP_LESSER;
    if (ip_1->addr64[0] > ip_2->addr64[0])
        return IP_GREATER;
    if (ip_1->addr64[1] < ip_2->addr64[1])
        return IP_LESSER;
    if (ip_1->addr64[1] > ip_2->addr64[1])
        return IP_GREATER;
#endif

    return IP_EQUAL;
}

#if 0
/* XXX TODO, polish into a robust ip address abstraction api */
#include <arpa/inet.h>

#define IPADDR_STRLEN INET6_ADDRSTRLEN

const char *ip_ntop(const struct ipaddr *src, char *dst, int size)
{
    if (size < IPADDR_STRLEN)
        return NULL;

    return inet_ntop(src->family, src, dst, size);
}

const ip_pton
inet_pton

/* 
 * Check if an ip address is private
 */
static inline ip_is_private(struct ipaddr *ip)
{
    /* check for ipv6 */
    if (ip->addr32[1] == 0 &&
        ip->addr32[2] == 0 &&
        ip->addr32[3] == 0)
    {
    }
}
#endif

#endif /* PACKET_IPADDR_H */
