/* Copyright(c) 2010-2012, Victor J. Roemer. All Rights Reserved.
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
 * CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Layer 3 Defragmentation. Plays nicely with libpacket.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#ifdef OPENBSD
# define IPPROTO_SCTP 132
# include <netinet/in.h>
# include <netinet/in_systm.h>
#endif

#include <netinet/ip.h>

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>

#include "timequeue.h"
#include "hashtable.h"


#include <packet.h>
//#include "mesg.h"
//#include "readconf.h"
#include "defragment.h"

#ifdef DEBUG
# include "print-data.h"
#endif

struct frag_key
{
    struct ipaddr srcaddr;
    struct ipaddr dstaddr;
    uint32_t id;
    uint8_t protocol;
};

struct frag
{
    struct frag *next;
    struct frag *prev;

    int offset;
    int size;
    bool mf;
    void *data;
};

struct frag_list
{
    struct frag *head;
    struct frag *tail;
    int size;

    unsigned packet_count;
    int acquired_bytes;
    int flush_bytes;
    bool have_last;
};

typedef enum OVERLAP_TYPE
{
    OVERLAP_NONE = 0,
    OVERLAP_EXACT,
    OVERLAP_SHORTER,
    OVERLAP_LONGER,
    OVERLAP_STARTS_BEFORE,
    OVERLAP_STARTS_AFTER,
    OVERLAP_STAGGERS_RIGHT,
    OVERLAP_STAGGERS_LEFT,
    OVERLAP_DWARFS_EXISTING,
    OVERLAP_DWARFED_BY_EXISTING,
    OVERLAP_ERROR = -1
} OVERLAP_TYPE;

/* Fragment Table Management Code */
int frag_table_remove(struct frag_key *, struct frag_list *);
struct frag_list *frag_table_get(struct frag_key *key);
int frag_table_insert(struct frag_key *, struct frag_list *);

/* Debugging Stuff */
int frag_print(struct frag *frag);
int frag_list_print(struct frag_list *list);

/* Fragment List Management Code */
struct frag_list * frag_list_create();
int frag_list_destroy(struct frag_list *list);
int frag_list_delete_element(struct frag_list *list, struct frag *frag);
int frag_list_pop(struct frag_list *list, struct frag *frag);
int frag_list_insert(struct frag_list *list, struct frag *frag);
uint8_t *frag_list_join(struct frag_list *list);
int find_frag_overlap(struct frag_list *, struct frag *, struct frag **);
int _frag_timeout_queue_task(const void *p_key);
int frag_key_compare(const void *p_key_1, const void *p_key_2);

/* Insertion models */
int frag_insert_first(struct frag_list *, struct frag *);
int frag_insert_last(struct frag_list *, struct frag *);
int frag_insert_linux(struct frag_list *, struct frag *);
int frag_insert_bsd(struct frag_list *, struct frag *);
int frag_insert_bsdright(struct frag_list *, struct frag *);
int frag_insert_windows(struct frag_list *, struct frag *);
int frag_insert_solaris(struct frag_list *, struct frag *);

int(*frag_insert_model)(struct frag_list *, struct frag *)
    = &frag_insert_first;

static Hash *fragtable = NULL;
struct tmq *timeout_queue;

/******************************************************************************
 * Fragment List Table Management Code
 *****************************************************************************/

/* Create Frag Tree
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_table_init()
{
#warning "frag_max_mem should be user defined"
    //fragtable = hash_create(options.frag_max_mem);
    fragtable = hash_create(4096);
    if(fragtable == NULL)
        return -1;

#warning "frag_age_limit should be user defined"
    //timeout_queue = tmq_create(options.frag_age_limit);
    timeout_queue = tmq_create(60);
    if(timeout_queue == NULL)
        return -1;

    timeout_queue->compare = frag_key_compare;
    timeout_queue->task = _frag_timeout_queue_task;

#ifdef ENABLE_PTHREADS
    tmq_start(timeout_queue);
#endif

    return 0;
}

/* Destroy Frag Table
 *
 * Will destroy the entire tree, and destory each of the fragment lists + 
 * fragments in the tree.
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_table_finalize()
{
    struct frag_list *it;
    unsigned i;
    const void *key;

    if(!fragtable)
        return -1;

#ifdef ENABLE_PTHREADS
    tmq_stop(timeout_queue);
#endif
    tmq_destroy(timeout_queue);

    for(it = hash_first(fragtable, &i, &key); it;
         it = hash_next(fragtable, &i, &key))
        frag_table_remove((struct frag_key *) key, it);

    hash_destroy(fragtable);

    return 0;
}

/* Frag Table Remove
 *
 * Remove a fragment list from the table
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_table_remove(struct frag_key *key, struct frag_list *list)
{
    if(list == NULL)
        return -1;

    hash_remove(fragtable, key, sizeof *key);

    frag_list_destroy(list);

    return 0;
}

/* Lookup Frag Tracker 
 *
 * Find an existing frag list in the table
 *
 * @param   pointer to the key to lookup
 *
 * @return  a pointer to the list
 *          NULL if no fragment lists are found
 */
struct frag_list *
frag_table_find(struct frag_key *key)
{
    return hash_get(fragtable, key, sizeof *key);
}

struct frag_list *
frag_table_get(struct frag_key *key)
{
    struct frag_list *list;

    if((list = frag_table_find(key)) == NULL) {
        if((list = frag_list_create()) == NULL)
            return NULL;

        else if((frag_table_insert(key, list) < 0))
            return NULL;
    }

    return list; 
}



/* Insert a new list into the fragment list table 
 *
 * @param   pointer to the key
 *
 * @return  NULL on failure 
 *          Pointer to new fragment list
 */
int
frag_table_insert(struct frag_key *key, struct frag_list *list)
{
    if(hash_insert(fragtable, list, key, sizeof *key) < 0)
        return -1;

    return 0;
}


/******************************************************************************
 * Fragment List Management Code
 *
 *****************************************************************************/

/* Frag New
 *
 * Return a new fragment given a set of parameters
 *
 * @return NULL on failure
 *         frag * on success
 */
struct frag *
frag_new(int offset, int size, bool mf, const uint8_t *addr)
{
    struct frag *frag;
    
    frag = malloc(sizeof(*frag) + size);
    if(frag == NULL)
        return NULL;

    frag->offset = offset;
    frag->size = size;
    frag->mf = mf;
    frag->data = &frag->data+1;

    if(addr) {
        memcpy(frag->data, addr, size);
    }

    return frag;
}

/* Frag Element Destroy
 *
 * Because you can actually have fragments which have not been inserted into
 * a list, we need a method of deleting those outside of the list
 * implementation.
 *
 * @return  -1 on failure
 *          0 on success
 */
void
frag_destroy(struct frag *frag)
{
    assert(frag != NULL);

    free(frag);

    return;
}

/* Frag List Init
 *
 * Create a new fragment list
 *
 * @return  NULL on failure
 *          struct frag_list * on success
 */
struct frag_list *
frag_list_create()
{
    struct frag_list *list;

    if((list = malloc(sizeof(*list))) == NULL)
        return NULL;

    memset(list, 0, sizeof(*list));

    list->flush_bytes = -1;
    list->acquired_bytes = 0;
    list->have_last = false;

    list->size = 0;
    list->head = NULL;
    list->tail = NULL;
    list->packet_count = 0;

    return list;
}

/* Frag List Delete Element
 *
 * Remove an element from a list, then delete it.
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_list_frag_delete(struct frag_list *list, struct frag *frag)
{
    if(frag_list_pop(list, frag))
        return -1;

    frag_destroy(frag);
    return 0;
}

/* Frag List Destroy
 *
 * Remove every element from a given list and remove the fragment list list
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_list_destroy(struct frag_list *list)
{
    while(list->size > 0)
        frag_list_frag_delete(list, list->head);

    free(list);

    return 0;
}

/* Frag List Remove
 *
 * Remove a given element from a given list
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_list_pop(struct frag_list *list, struct frag *frag)
{
    assert(list != NULL);
    assert(list->size != 0);
    assert(frag != NULL);

    if(frag == list->head)
    {
        list->head = frag->next;

        if(list->head == NULL)
            list->tail = NULL;
        else
            frag->next->prev = NULL;
    }
    else
    {
        frag->prev->next = frag->next;
        if(frag->next == NULL)
            list->tail = frag->prev;
        else
            frag->next->prev = frag->prev;
    }

    frag->next = NULL;
    frag->prev = NULL;

    list->size--;
    list->acquired_bytes -= frag->size;

    return 0;
}

/* Frag List Insert
 *
 * Add a new element to the tail of the list
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_list_insert(struct frag_list *list, struct frag *frag)
{
    assert(list != NULL);
    assert(frag != NULL);

    if(list->size == 0)
    {
        list->head = frag;
        list->tail = frag;
        list->head->prev = NULL;
        list->head->next = NULL;
    }

    else
    {
        frag->next = NULL;
        frag->prev = list->tail;

        list->tail->next = frag;
        list->tail = frag;
    }

    if(frag->mf == false)
    {
        list->have_last = true;
        list->flush_bytes = frag->offset + frag->size;
    }

    list->size++;
    list->acquired_bytes += frag->size;

    return 0;
}

/* Join Fragment List
 *
 * @param   list, fragment list containing the list to join.
 *
 * @return  pointer to reassembled data
 */
uint8_t *
frag_list_join(struct frag_list * list)
{
    struct frag *it;
    uint8_t *data;

    if(list == NULL || list->head == NULL)
        return NULL;

    data = malloc(list->acquired_bytes);
    if(data == NULL)
        return NULL;

    for(it = list->head; it; it = it->next)
    {
        if((it->offset + it->size) > list->acquired_bytes)
            continue;
        memcpy(data + it->offset, it->data, it->size);
    }

    return data;
}

#if 0 
// DEBUGGING CODE
/* Print a fragment
 *
 * XXX Primarily Debugging Code 
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_print(struct frag *frag)
{
    if(frag == NULL || frag->data == NULL)
        return -1;

    printf("Fragment Offset: %d\n", frag->offset);
    printf("Fragment Size:   %d\n", frag->size);
    printf("More Fragments:  %d\n", frag->mf);

    printf("Fragment Prev: %p\n",(void *)frag->prev);
    printf("Fragment Next: %p\n",(void *)frag->next);
    printf("Fragment Addr: %p\n",(void *)frag);
    printf("Fragment Data Addr: %p\n",(void *)frag->data);

    print_data(frag->data, frag->size);

    printf("\n");

    return 0;
}

/* Print out a fragment list
 *
 * XXX Primarily Debugging Code
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_list_print(struct frag_list *list)
{
    struct frag *it;

    if(list == NULL || list->head == NULL)
        return -1;

    printf("list->size =     %d\n", list->size);
    printf("list->acquired = %d\n", list->acquired_bytes);
    printf("list->flush_at = %d\n", list->flush_bytes);
    printf("list->havelast = %d\n\n", list->have_last);

    for(it = list->head; it; it = it->next)
        frag_print(it);

    return 0;
}
#endif /* DEBUG */

/* Find Fragment Overlap
 *
 * Figure out if a fragment overlaps any of the fragments in the list
 * of fragments.
 *
 * @param   head, pointer to the the list of fragments
 * @param   frag, the fragment to examine
 * @param   *old, pointer to a frag pointer to return the overlaped frag to
 *
 * @return  -1 on failure 
 *          1 - 5 for various fragment scenarios
 *          0 for no overlaps
 */
int
find_frag_overlap(struct frag_list *list, struct frag *frag,
    struct frag **old)
{
    struct frag *it;
    int frag_end, it_end;

    if(list == NULL || list->head == NULL || frag == NULL)
        return OVERLAP_ERROR;

    for(it = list->head; it; it = it->next)
    {
        if(old != NULL)
            *old = it;

        frag_end = frag->offset + frag->size;
        it_end = it->offset + it->size;
        
        /* exact overlap 
         * [AAAAAAAA]           <- original
         * [BBBBBBBB]           <- overlap
         */
        if(frag->offset == it->offset &&
            frag->size == it->size)
            return OVERLAP_EXACT;

        /* overlap shorter
         * [AAAAAAAABBBBBBBB]   <- original
         * [CCCCCCCC]           <- overlap
         */
        if(frag->offset == it->offset &&
            frag->size < it->size)
            return OVERLAP_SHORTER;

        /* overlap longer
         * [AAAAAAAA]           <- original
         * [BBBBBBBBCCCCCCCC]   <- overlap
         */
        if(frag->offset == it->offset &&
            frag->size > it->size)
            return OVERLAP_LONGER;
        
        /* overlap starts before
         *
         *         [BBBBBBBB]   <- original
         * [AAAAAAAACCCCCCCC]   <- overlap
         */
        if(frag->offset < it->offset &&
            frag_end == it_end)
            return OVERLAP_STARTS_BEFORE;

        /* overlap starts after 
         *
         * [AAAAAAAABBBBBBBB]   <- original
         *         [CCCCCCCC]   <- overlap
         */
        if(frag->offset > it->offset &&
            frag_end == it_end)
            return OVERLAP_STARTS_AFTER;

        /* XXX now comes the tricky ones */

        /* overlap staggers right 
         *
         * [AAAAAAAABBBBBBBB]           <- original
         *         [CCCCCCCCDDDDDDDD]   <- overlap
         */
        if(frag->offset > it->offset &&
            frag->offset < it_end    &&
            frag_end > it_end)
            return OVERLAP_STAGGERS_RIGHT;

        /* overlap staggers left
         *
         *         [AAAAAAAABBBBBBBB]   <- original
         * [CCCCCCCCDDDDDDDD]           <- overlap
         */
        if(frag->offset < it->offset &&
            frag_end > it->offset    &&
            frag_end < it_end)
            return OVERLAP_STAGGERS_LEFT;

        /* overlap dwarfs existing 
         *
         *         [AAAAAAAA]           <- original
         * [BBBBBBBBCCCCCCCCDDDDDDDD]   <- overlap
         */
        if(frag->offset < it->offset &&
            frag_end > it_end)
            return OVERLAP_DWARFS_EXISTING;

        /* overlap dwarfed by existing 
         *
         * [AAAAAAAABBBBBBBBCCCCCCCC]   <- original
         *         [DDDDDDDD]           <- overlap
         */
        if(frag->offset > it->offset &&
            frag_end < it_end)
            return OVERLAP_DWARFED_BY_EXISTING;
    }
    if(old != NULL)
        *old = NULL;

    /* no overlaps */
    return OVERLAP_NONE;
}

/*********************************************************************
 * Actual fragment code
 ********************************************************************/

/* frag_merge
 *
 * Merge the two fragments where src overwrites dst and the results
 * are put back into dst.
 *
 * TODO: fix parameter names
 *
 * new is a pointer to the new fragment to be created
 * dst is a pointer to the original fragment
 * src is a pointer to the fragment to overlay overtop of dest
 *
 * TODO: the new fragment should have the same mf value as src
 *
 * @return  -1 on failure
 *          0 on success
 */
int
frag_merge(struct frag **new, struct frag *dst, struct frag *src)
{
    int _off = 0, _size = 0;

    assert(dst != NULL);
    assert(src != NULL);

    if(dst->offset < src->offset)
        _off = dst->offset;
    else
        _off = src->offset;

    if((dst->offset + dst->size) >(src->offset + src->size))
        _size = (dst->offset + dst->size) - _off;
    else
        _size = (src->offset + src->size) - _off;

    if((*new = frag_new(_off, _size, src->mf, NULL)) == NULL)
        return -1;

    _off = 0;
    if(dst->offset > src->offset)
        _off = dst->offset - src->offset;
    memcpy((uint8_t *)((*new)->data) + _off, dst->data, dst->size);

    _off = 0;
    if(src->offset > dst->offset)
        _off = src->offset - dst->offset;
    memcpy((uint8_t *)((*new)->data) + _off, src->data, src->size);

    return 0;
}

/* Do the frag merge junk and then delete dst and src
 */
int
frag_merge_and_destroy(struct frag **new, struct frag *dst, struct frag *src)
{
    if(frag_merge(new, dst, src))
        return -1;

    frag_destroy(dst);
    frag_destroy(src);

    return 0;
}

/* Insert First Frag
 *
 * This function inserts fragments based on a first come first serve
 * basis.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_first(struct frag_list *list, struct frag *frag)
{
    struct frag *new, *orig;

    if (find_frag_overlap(list, frag, &orig) > 0)
    {
        frag_list_pop(list, orig);
        frag_merge_and_destroy(&new, frag, orig);
        frag_insert_first(list, new);
    }
    else
    {
        frag_list_insert(list, frag);
    }

    return 0;
}

/* Insert Last Frag
 *
 * This function inserts fragments based on a first come first serve
 * basis.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_last(struct frag_list *list, struct frag *frag)
{
    struct frag *orig, *new;

    if(find_frag_overlap(list, frag, &orig) > 0)
    {
        frag_list_pop(list, orig);
        frag_merge_and_destroy(&new, orig, frag);
        frag_insert_last(list, new);
    }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* Insert Linux Frag
 *
 * Linux favors an original fragment with an offset that is less than a
 * subsequent fragment.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_linux(struct frag_list *list, struct frag *frag)
{
    struct frag *new=NULL, *orig;
    int overlap;

    if((overlap = find_frag_overlap(list, frag, &orig)) > 0)
        switch(overlap)
        {
        case OVERLAP_DWARFED_BY_EXISTING:
        case OVERLAP_STAGGERS_RIGHT:
        case OVERLAP_STARTS_AFTER:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_linux(list, new);
            break;

        default:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_linux(list, new);
            break;
        }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* Insert BSD Frag
 *
 * BSD favors an original fragment with an offset that is less than or equal to
 * a subsequent fragment
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_bsd(struct frag_list *list, struct frag *frag)
{
    struct frag *new = NULL, *orig;
    int overlap;

    if((overlap = find_frag_overlap(list, frag, &orig)) > 0)
    {
        switch(overlap)
        {
        case OVERLAP_EXACT:
            frag_destroy(frag);
            break;

        case OVERLAP_STARTS_BEFORE:
        case OVERLAP_DWARFS_EXISTING:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_bsd(list, new);
            break;

        default:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_bsd(list, new);
            break;
        }
    }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* Insert BSD-Right Frag
 *
 * BSD-Right favors a subsequent fragment when the original fragment has an
 * offset that is less than or equal to the subsequent one.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_bsdright(struct frag_list *list, struct frag *frag)
{
    struct frag *new, *orig;
    int overlap;

    if((overlap = find_frag_overlap(list, frag, &orig)) > 0)
        switch(overlap)
        {
        case OVERLAP_EXACT:
        case OVERLAP_LONGER:
        case OVERLAP_STAGGERS_RIGHT:
        case OVERLAP_DWARFED_BY_EXISTING:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_bsdright(list, new);
            break;

        default:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_bsdright(list, new);
            break;
        }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* Insert Windows Frag
 *
 * This function inserts fragments based on a first come first serve
 * basis.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_windows(struct frag_list *list, struct frag *frag)
{
    struct frag *new, *orig;
    int overlap;

    if((overlap = find_frag_overlap(list, frag, &orig)) > 0)
        switch(overlap)
        {
        case OVERLAP_DWARFS_EXISTING:
            frag_list_pop(list, orig);
            frag_insert_windows(list, frag);
            break;

        default:
            frag_list_pop(list, orig);
            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_windows(list, new);
            break;
        }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* Insert Solaris Frag
 *
 * This function inserts fragments based on a first come first serve
 * basis.
 *
 * @param   list, pointer to the list to insert the fragment
 * @param   frag, the fragment to insert
 *
 * @return  pointer to the fragment inserted, NULL if we decided not to
 *          insert.
 */
int
frag_insert_solaris(struct frag_list *list, struct frag *frag)
{
    struct frag *new, *orig;
    int overlap;

    if((overlap = find_frag_overlap(list, frag, &orig)) > 0)
        switch(overlap)
        {
        case OVERLAP_STARTS_BEFORE:
        case OVERLAP_DWARFS_EXISTING:
            frag_list_pop(list, orig);

            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_solaris(list, new);
            break;

        default:
            frag_list_pop(list, orig);

            frag_merge_and_destroy(&new, orig, frag);
            frag_insert_solaris(list, new);
            break;
        }
    else
        frag_list_insert(list, frag);

    return 0;
}

/* timeout_queue_callbacks */
int
_frag_timeout_queue_task(const void *p_key)
{
    struct frag_list *list = frag_table_find((struct frag_key *)p_key);

    if(list == NULL)
        return -1;

    return frag_table_remove((struct frag_key *)p_key, list);
}

int
frag_key_compare(const void *p_key_1, const void *p_key_2)
{
    struct frag_key *key_1, *key_2; 
    key_1 =(struct frag_key *)p_key_1;
    key_2 =(struct frag_key *)p_key_2;

    if ((ip_compare(&key_1->srcaddr, &key_2->srcaddr) == IP_EQUAL) &&
        (ip_compare(&key_1->dstaddr, &key_2->dstaddr) == IP_EQUAL) &&
        (key_1->id == key_2->id) && (key_1->protocol == key_2->protocol))
        return 0;

    return 1;
}

/* Defragment
 *
 * Take a partialy decoded packet and reassemble it with other
 * fragments
 *
 * @param   p, Pointer to the decoded Packet structure
 *
 * @return  -1 on failure
 *          0 on success
 */
int
defragment(Packet *p)
{
    int ret = -1;

    /* Create a fragment key from the packet structure
     */
    struct frag_key key;
    memset(&key, 0, sizeof(key));
    key.srcaddr = packet_srcaddr(p);
    key.dstaddr = packet_dstaddr(p);
    key.id = packet_id(p);
    key.protocol = packet_protocol(p);

    /* Lookup or create a new fragment list
     */
    struct frag_list *list;
    if((list = frag_table_get(&key)) == NULL)
        return -1;

    list->packet_count++;

    /* Create or locate an existing timeout queue element
     * Requeue the element
     */
    struct tmq_element *tmq_elem;
    if((tmq_elem = tmq_find(timeout_queue, &key)) == NULL) {
        tmq_elem = tmq_element_create(&key, sizeof(key));
        tmq_insert(timeout_queue, tmq_elem);
    }
    else
        tmq_bump(timeout_queue, tmq_elem);

    /* Create a new fragment
     * Insert the fragment into the fragment list
     */ 
    struct frag *frag;
    frag = frag_new(packet_frag_offset(p)*8, packet_paysize(p),
        packet_frag_mf(p), packet_payload(p));

    if(frag == NULL)
        return -1;

    frag_insert_model(list, frag);

    /* Check if the packet was successfully reassembled
     */
    if(list->have_last && (list->acquired_bytes >= list->flush_bytes)) {
        uint8_t *      payload = frag_list_join(list);
        const uint32_t paysize = list->flush_bytes;

        tmq_delete(timeout_queue, tmq_elem);

        packet_set_payload(p, payload, paysize);

        frag_table_remove(&key, list);

        ret = 0;
    }

    /* If we are not using a threaded timer then check for
     * timed out elements
     */
#ifndef ENABLE_PTHREADS
    tmq_timeout(timeout_queue);
#endif

    return ret;
}

/* Set Defrag Method
 * The verification routine for readconf.c
 */
int
set_defrag_method(const char *value, const char *filename,
    unsigned linenum, int *error)
{
    if(strcasecmp(value, "first") == 0) {
        frag_insert_model = &frag_insert_first;
        return 0;
    }
    else if(strcasecmp(value, "last") == 0) {
        frag_insert_model = &frag_insert_last;
        return 0;
    }
    else if(strcasecmp(value, "linux") == 0) {
        frag_insert_model = &frag_insert_linux;
        return 0;
    }
    else if(strcasecmp(value, "bsd") == 0) {
        frag_insert_model = &frag_insert_bsd;
        return 0;
    }
    else if(strcasecmp(value, "bsd-right") == 0) {
        frag_insert_model = &frag_insert_bsdright;
        return 0;
    }
    else if(strcasecmp(value, "windows") == 0) {
        frag_insert_model = &frag_insert_windows;
        return 0;
    }
    else if(strcasecmp(value, "solaris") == 0) {
        frag_insert_model = &frag_insert_solaris;
        return 0;
    }
    else {
        fprintf(stderr, "Bad defrag method %s:%d", filename, linenum);
        return -1;
    }

    return -1;
}
