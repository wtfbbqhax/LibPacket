/* Copyright  (c) 2012, Victor J Roemer. All Rights Reserved.
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
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//
//  hashtable.h
//  pcapstats
//
//  Lightweight hashtable implementation in C.
//
//  Created by Victor J. Roemer on 3/4/12.
//  Copyright  (c) 2012 Victor J. Roemer. All rights reserved.

//  Modified by Victor J. Roemer Jan 2, 2015:
//      - Merge hashdigest.[ch] into hashtable.[ch]
//      - fixup header to be more aligned to my current style nitpicks.

#ifndef VJR2015_HASHTABLE_H
#define VJR2015_HASHTABLE_H

// XXX Include the following headers in your code before including this file.
//#include <stdlib.h>
//#include <stdbool.h>
//#include <sys/types.h>

typedef struct _Hash Hash;

void    digest_init (unsigned buckets);
unsigned long fnv1a_digest (const void *buf, size_t len, unsigned long hval);

Hash*   hash_create (size_t buckets);
void    hash_destroy (Hash*);
void    hash_dump   (Hash*);
#define hash_size(X) \
  ((X)->size)

// Basic hash table operations (insert, remove and retrieve[get]).
int     hash_insert (Hash*, void *data, void *key, size_t keysize);
void*   hash_remove (Hash*, const void *key, size_t keysize);
void*   hash_get    (Hash*, void *key, size_t keysize);

// Functions to Iterate the entries in the hash table.
void*   hash_first (Hash*, unsigned *it, const void **key);
void*   hash_next  (Hash*, unsigned *it, const void **key);

#endif /* VJR2015_HASHTABLE_H */
