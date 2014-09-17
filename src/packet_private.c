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
#include <stdint.h>

#include "packet_private.h"

/* convenient helper */
#define current_layer (packet->layer_count-1)

/* Insert a protocol layer into the packet */
inline int
packet_layer_ins(Packet *packet, const uint8_t *start, unsigned size,
 PROTOCOL proto)
{
    if (packet->layer_count == MAX_LAYERS)
    {
        return -1;
    }

    packet->layer_count++;

    /* index is count - 1 */
    packet->layer[current_layer].protocol = proto;
    packet->layer[current_layer].start = start;
    packet->layer[current_layer].size = size;

    return 0;
}

/* Remove a protocol layer from the packet
 *
 * NOTE: to remove a layer all you need to do is reduce the count.
 * this saves time by not having to memset the structure */
inline int
packet_layer_rem(Packet *packet)
{
    if (packet->layer_count == 0)
    {
        return -1;
    }

    packet->layer_count--;

    return 0;
}

/* Assign a pointer to the current layer
 *
 */
inline Protocol *
packet_layer_current(Packet *packet)
{
    if (packet->layer_count == 0)
    {
        return NULL;
    }

    return &packet->layer[current_layer];
}

