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
#include "checksum.h"

/** Checksum
 * Pseudo header is sized for ipv6 which is fine for ipv4 as well.
 * As long as I remember to zero out the extra address space.
 */

uint16_t
checksum(uint16_t *addr, struct pseudo_hdr *pseudo, unsigned len)
{
    uint32_t sum = 0;

    if (pseudo != NULL)
    {
        uint16_t *p16 = (uint16_t *)pseudo;

        sum += p16[0];
        sum += p16[1];
        sum += p16[2];
        sum += p16[3];
        sum += p16[4];
        sum += p16[5];
        sum += p16[6];
        sum += p16[7];
        sum += p16[8];
        sum += p16[9];
        sum += p16[10];
        sum += p16[11];
        sum += p16[12];
        sum += p16[13];
        sum += p16[14];
        sum += p16[15];
        sum += p16[16];
        sum += p16[17];
    }

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(unsigned char *) addr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}
