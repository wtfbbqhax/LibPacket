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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

#ifdef HAVE_CONFIG
#include <config.h>
#endif

#include "timequeue.h"

#define UNUSED __attribute__((unused))

/** Timeout Queue Create
 * @return pointer to new tmq
 */
struct tmq *
tmq_create (unsigned timeout)
{
    struct tmq *tmq;

    if ((tmq = malloc (sizeof (*tmq))) == NULL)
        return NULL;

    tmq->size = 0;
    tmq->head = NULL;
    tmq->tail = NULL;
    tmq->timeout = timeout ? timeout : TIMEOUT;

#ifdef ENABLE_PTHREADS
    pthread_mutex_init (&tmq->lock, NULL);
#endif

    tmq->state = QUEUE_STOPPED;

    return tmq;
}

/** Start the clock 
 * @return 0 on success, -1 on failure
 */
#ifdef ENABLE_PTHREADS
int
tmq_start (struct tmq *tmq)
{
    if (tmq == NULL)
        return -1;

    if (tmq->state != QUEUE_STOPPED)
        return -1;

    if (pthread_create (&tmq->thread, NULL, tmq_thread, (void *)tmq))
        return -1;

    tmq->state = QUEUE_STARTED;

    return 0;
}
#else
int
tmq_start (struct tmq *tmq UNUSED)
{
    return -1;
}
#endif

/** Timeout Queue Stop
 * @return 0 on success, -1 on failure
 */
#ifdef ENABLE_PTHREADS
int
tmq_stop (struct tmq *tmq)
{
    if (tmq == NULL)
        return -1;

    if (tmq->state != QUEUE_STARTED)
        return -1;

    tmq->state = QUEUE_STOPPED;

    if (pthread_cancel (tmq->thread))
        return -1;

    return 0;
}
#else
int
tmq_stop (struct tmq *tmq UNUSED)
{
    return -1;
}
#endif

/** Timeout Queue Element Create
 * @return pointer to a new tmq element
 */
struct tmq_element *
tmq_element_create (const void *p_key, unsigned int i_key_size)
{
    struct tmq_element *elem;

    if (p_key == NULL || i_key_size == 0)
        return NULL;


    if ((elem = malloc (sizeof (*elem))) == NULL)
        return NULL;

    if ((elem->key = malloc (i_key_size)) == NULL)
    {
        free (elem);
        return NULL;
    }
    memcpy (elem->key, p_key, i_key_size);

    elem->prev = NULL;
    elem->next = NULL;
    gettimeofday (&elem->time, NULL);

    return elem;
}

/** Timeout Queue Destroy
 * @return -1 on failure, 0 on success
 */
int
tmq_destroy (struct tmq *tmq)
{
    if (tmq == NULL)
        return -1;

    if (tmq->state == QUEUE_STARTED)
        return -1;

    while (tmq->size > 0)
        tmq_delete (tmq, tmq->head);

    free (tmq);

    tmq = NULL;

    return 0;
}

/** Timeout Queue Pop
 * Remove the element from the list
 * @return -1 on failure, 0 on success
 */
int
tmq_pop (struct tmq *tmq, struct tmq_element *elem)
{
    if (tmq == NULL || tmq->size == 0 || elem == NULL)
        return -1;

#ifdef ENABLE_PTHREADS
    pthread_mutex_lock (&tmq->lock);
#endif

    if (elem == tmq->head)
    {
        tmq->head = elem->next;

        if (tmq->head == NULL)
            tmq->tail = NULL;
        else
            tmq->head->prev = NULL;
    }
    else
    {
        elem->prev->next = elem->next;

        if (elem->next == NULL)
            tmq->tail = elem->prev;
        else
            elem->next->prev = elem->prev;
    }

    elem->prev = NULL;
    elem->next = NULL;

    tmq->size--;

#ifdef ENABLE_PTHREADS
    pthread_mutex_unlock (&tmq->lock);
#endif

    return 0;
}

/** Timeout Queue Delete
 * Delete an element from the list
 * @return -1 on failure, 0 on success
 */
int
tmq_delete (struct tmq *tmq, struct tmq_element *elem)
{
    if (tmq == NULL || elem == NULL || elem->key == NULL)
        return -1;

    if (tmq_pop (tmq, elem))
        return -1;

    free (elem->key);
    free (elem);

    return 0;
}

/** Timeout Queue Element Insert
 * @return -1 on failure, 0 on success
 */
int
tmq_insert (struct tmq *tmq, struct tmq_element *elem)
{
    if (tmq == NULL || elem == NULL)
        return -1;

#ifdef ENABLE_PTHREADS
    pthread_mutex_lock (&tmq->lock);
#endif

    if (tmq->size == 0)
    {
        tmq->head = elem;
        tmq->tail = elem;
        tmq->head->prev = NULL;
        tmq->head->next = NULL;
    }
    else
    {
        elem->next = tmq->head;
        elem->prev = NULL;
        tmq->head->prev = elem;
        tmq->head = elem;
    }

    tmq->size++;
    gettimeofday (&elem->time, NULL);

#ifdef ENABLE_PTHREADS
    pthread_mutex_unlock (&tmq->lock);
#endif

    return 0;
}

/** Update the atime on the element and bump it up the tmq
 * @return -1 on failure, 0 on success 
 */
int
tmq_bump (struct tmq *tmq, struct tmq_element *elem)
{
    if (tmq == NULL || elem == NULL)
        return -1;

    if (tmq_pop (tmq, elem))
        return -1;

    tmq_insert (tmq, elem);

    return 0;
}

/** Timeout Queue Find
 * @return pointer to matching element
 */
struct tmq_element *
tmq_find (struct tmq *tmq, const void *p_key)
{
    struct tmq_element *it;

    if (tmq == NULL || p_key == NULL)
        return NULL;

    for (it = tmq->head; it; it = it->next)
        if (tmq->compare (p_key, it->key) == 0)
            return it;

    return NULL;
}

/** Timeout old elements in the tmq 
 * @return number of elements timed out
 */
int
tmq_timeout (struct tmq *tmq)
{
    struct tmq_element *it;
    struct timeval timeout;
    int removed = 0;

    if (tmq == NULL)
        return -1;

    gettimeofday (&timeout, NULL);
    timeout.tv_sec -= TIMEOUT;

    for (it = tmq->tail; it; it = tmq->tail)
    {
        if (it->time.tv_sec > timeout.tv_sec)
            break;

        if (tmq->task != NULL)
            tmq->task (it->key);

        tmq_delete (tmq, it);
        removed++;
    }

    return removed;
}

/** Timeout Thread
 * @return void *
 */
#ifdef ENABLE_PTHREADS
void *
tmq_thread (void *args)
{
    struct tmq *tmq = (struct tmq *)args;
    struct timespec timeout;
    timeout.tv_sec = TIMEOUT_INTERVAL;
    timeout.tv_nsec = 0;

    pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype (PTHREAD_CANCEL_DEFERRED, NULL);

    while (1)
    {
        nanosleep(&timeout, NULL);
        tmq_timeout (tmq);
    }

    return (void *)0;
}
#else
void *
tmq_thread (void *args UNUSED)
{
    return (void *)-1;
}
#endif
