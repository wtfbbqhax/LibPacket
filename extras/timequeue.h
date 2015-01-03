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
#ifndef __TIMEOUT_QUEUE_H__
#define __TIMEOUT_QUEUE_H__

#include <sys/time.h>
#include <pthread.h>

/** Default Queue Time value (in seconds)
 */
#define DEFAULT_TIMEOUT 60

#ifndef TIMEOUT
#   define TIMEOUT DEFAULT_TIMEOUT
#endif

/** Schedule check interval 
 * how often to check for expired elements
 */
#define DEFAULT_TIMEOUT_INTERVAL 1

#ifndef TIMEOUT_INTERVAL
#   define TIMEOUT_INTERVAL DEFAULT_TIMEOUT_INTERVAL
#endif

/** State of the tmq
 */
typedef enum
{
    QUEUE_STOPPED,
    QUEUE_STARTED
} QUEUE_STATE;

/** Schedule Queue Element
 */
struct tmq_element
{
    struct tmq_element *prev;
    struct tmq_element *next;
    struct timeval time;        /* access time */
    void *key;
};

/** Schedule Queue Structure
 */
struct tmq
{
    struct tmq_element *head;
    struct tmq_element *tail;
    int tmq;
    int size;
    int timeout;

    pthread_t thread;
    pthread_mutex_t lock;
    QUEUE_STATE state;

    int (*compare) (const void *p1, const void *p2);
    int (*task) (const void *p);
};

/** Timer routine
 */
extern void *tmq_thread (void *args);

/** Create a new tmq 
 */
extern struct tmq *tmq_create ();

/** Start the expiration thread for the tmq
 */
int tmq_start (struct tmq *tmq);

/** Stop the expiration thread fro the tmq
 */
int tmq_stop (struct tmq *tmq);

/** Create a new tmq element
 */
extern struct tmq_element *tmq_element_create (const void *p_key,
                                                   unsigned int i_key_size);

/** Destroy a tmq 
 */
extern int tmq_destroy (struct tmq *tmq);

/** Pop an element out of the tmq
 */
extern int tmq_pop (struct tmq *tmq, struct tmq_element *elem);

/** Delete an element from the tmq
 */
extern int tmq_delete (struct tmq *tmq, struct tmq_element *elem);

/** Insert an element into the tmq
 */
extern int tmq_insert (struct tmq *tmq, struct tmq_element *elem);

/** Push element to top of tmq and update access time
 */
extern int tmq_bump (struct tmq *tmq, struct tmq_element *elem);

/** Find an element that matches the data
 */
extern struct tmq_element *tmq_find (struct tmq *tmq,
                                         const void *p_key);

/** Timeout old elements in the tmq
 */
extern int tmq_timeout (struct tmq *tmq);

#endif /* __TIMEOUT_QUEUE_H__ */
