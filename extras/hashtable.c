/* Copyright (c) 2012, Victor J Roemer. All Rights Reserved.
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

//
//  hashtable.c
//  Open address hash table using quadratic probing to avoid
//  collisions. Modeled loosely after Googles sparse hash table.
//
//  Created by Victor J. Roemer on 3/4/12.
//  Copyright (c) 2012 Victor J. Roemer. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/cdefs.h>

#include <time.h>

#include <assert.h>


#include "hashtable.h"

/* __flexarr crap stolen from dnet. */
#undef __flexarr
#if defined(__GNUC__) && ((__GNUC__ > 2) || \
    (__GNUC__ == 2 && __GNUC_MINOR__ >= 97))
# define __flexarr  []
#else
# ifdef __GNUC__
#  define __flexarr [0]
# else
#  if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#   define __flexarr    []
#  elif defined(_WIN32)
/* MS VC++ */
#   define __flexarr    []
#  else
/* Some other non-C99 compiler. Approximate with [1]. */
#   define __flexarr    [1]
#  endif
# endif
#endif

typedef struct
{
    bool filled;
    void *value;
    size_t keysize;
#if __STDC_VERSION__ >= 199901L
    char key __flexarr;
#else
    void *key;
#endif
} Bucket;

struct _Hash
{
    size_t buckets;
    size_t size;
    Bucket **table;
};

/*
==============
Data 'hashing' routines.
==============
*/
static int seed;

void digest_init(unsigned buckets)
{
    srand(time(0));
    seed = (rand() * rand() % buckets);
}

unsigned long fnv1a_digest(const void *buf, size_t len, unsigned long hval)
{
    unsigned char *start = (unsigned char *)buf;
    unsigned char *end = start + len;

    while (start < end) {
        hval ^= (unsigned char)*start++;
        hval *= 0x01000193;
        hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    }

    return hval + seed;
}

/*
==============
Hash table managment code below.
==============
*/

/*
 * hash_create
 *
 * Allocate space for a new table and initialize all the table elements.
 */
Hash *hash_create(size_t buckets)
{
    size_t i;

    Hash *this = calloc(1, sizeof(*this));
    if (this == NULL) {
        return NULL;
    }

    this->table = (Bucket **)calloc(buckets, sizeof(*(this->table)));
    if (this->table == NULL) {
        free(this);
        return NULL;
    }

    this->buckets = buckets;
    this->size = 0;

    for (i = 0; i < this->buckets; ++i) {
        this->table[i] = NULL;
    }

    digest_init(buckets);

    return this;
}

/*
 * hash_destroy
 *
 * Will not remove entries in the table so make sure you take care of that.
 */
void hash_destroy(Hash *this)
{
    size_t i;

    assert(this != NULL);
    assert(this->table != NULL);
    assert(this->size == 0);

    for (i = 0; i < this->buckets; ++i)
        free(this->table[i]);

    free(this->table);
    free(this);
}

/*
 * bucket_create
 *
 * Create a new bucket.
 */
static inline Bucket *bucket_create(void *value, void *key, size_t keysize)
{
    Bucket *bucket = NULL;
    if ((bucket = malloc(keysize + sizeof(*bucket))) == NULL) {
        return NULL;
    }

    bucket->keysize = keysize;
    bucket->value = value;
    bucket->filled = true;

    /* store key with bucket, bucket->key will point into itself */
#if __STDC_VERSION__ < 199901L
    bucket->key = &bucket->key+1;
#endif
    memcpy(bucket->key, key, keysize);

    return bucket;
}

/* 
 * hash_insert
 *
 * Insert a new key/value pair.
 */
int hash_insert(Hash *this, void *value, void *key, size_t keysize)
{
    size_t i;
//    if ((float)(this->size/this->buckets) > 0.8f) {
//        printf("Loadfactor == %f\n", (float)(this->size/this->buckets));
//        return -1;
//    }

    unsigned long idx = fnv1a_digest(key, keysize, 0x811c9dc5) % this->buckets;
    
    for (i = 1; i < this->buckets; ++i) {
        if (this->table[idx] == NULL) {
            this->table[idx] = bucket_create(value, key, keysize);
            this->size++;
            return 0;
        }
        /** FIXME: if key sizes differ, than the bucket really needs to be
         * updated. */
        else if (this->table[idx]->filled == false) {
            this->table[idx]->filled = true;
            memcpy(this->table[idx]->key, key, keysize);
            this->table[idx]->keysize = keysize;
            this->table[idx]->value = value;
            this->size++;
            return 0;
        }

        /* bucket was already filled, find a new bucket */
        idx = (idx + i*i) % this->buckets;
    }
    
    return -1;
}

/*
 * hash_remove
 *
 * Remove key/value pair from table and return the value.
 */
void *hash_remove(Hash *this, const void *key, size_t keysize)
{
    size_t i;
    unsigned long idx = fnv1a_digest(key, keysize, 0x811c9dc5) % this->buckets;

    for (i = 0; i < this->buckets; i++) {
        if (this->table[idx] == NULL)
            return NULL;

        if (this->table[idx]->filled == false) {
            idx = (idx + i*i) % this->buckets;
            continue;
        }

        if (memcmp(key, this->table[idx]->key,
            this->table[idx]->keysize) == 0) {
            this->table[idx]->filled = false;
            this->size--;
            return this->table[idx]->value;
        }

        idx = (idx + i*i) % this->buckets;
    }
    
    return NULL;
}

/*
 * hash_get
 *
 * Return value for the key in the table.
 */
void *hash_get(Hash *this, void *key, size_t keysize)
{
    size_t i;
    unsigned long idx = fnv1a_digest(key, keysize, 0x811c9dc5)
    % this->buckets;

    for (i = 0; i < this->buckets; i++) {
        if (this->table[idx] == NULL)
            return NULL;

        if (this->table[idx]->filled == false)
            continue;

        else 
        if (memcmp(key, this->table[idx]->key,
            this->table[idx]->keysize) == 0)
            return this->table[idx]->value;

        idx = (idx + i*i) % this->buckets;
    }
    
    return NULL;
}

/*
 * hash_first
 *
 * return the first element in the hash table.
 */
void *hash_first(Hash *this, unsigned *it, const void **key)
{
    for (*it = 0; (*it) < this->buckets; (*it)++) {
        if (this->table[*it] == NULL)
            continue;
        if (this->table[*it]->filled) {
            *key = this->table[*it]->key;
            return this->table[*it]->value;
        }
    }

    return NULL;
}

/*
 * hash_next
 *
 * return the next element in the hash table.
 */
void *hash_next(Hash *this, unsigned *it, const void **key)
{
    for ((*it)++; (*it) < this->buckets; (*it)++) {
        if (this->table[*it] == NULL)
            continue;
        if (this->table[*it]->filled) {
            *key = this->table[*it]->key;
            return this->table[*it]->value;
        }
    }

    return NULL;
}

/*
 * hash_dump
 *
 * display the contents of the hash table.
 */
void hash_dump(Hash *this)
{
    size_t i;
    unsigned long memuse = sizeof(*this) + ((sizeof(Bucket)+16)*this->buckets);
    printf("Fixed memory usage = %lu\n", memuse);
    for (i = 1; i < this->buckets; ++i) {
        if (this->table[i] != NULL && this->table[i]->filled)
            printf("[%u][ full ]\n", (unsigned)i);
    }
}
