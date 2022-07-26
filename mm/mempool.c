// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/mempool.c
 *
 *  memory buffer pool support. Such pools are mostly used
 *  for guaranteed, deadlock-free memory allocations during
 *  extreme VM load.
 *
 *  started by Ingo Molnar, Copyright (C) 2001
 *  debugging by David Rientjes, Copyright (C) 2015
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/writeback.h>
#include "slab.h"

/*
 * A commonly used alloc and free fn.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
    struct kmem_cache *mem = pool_data;
    VM_BUG_ON(mem->ctor);
    return kmem_cache_alloc(mem, gfp_mask);
}
EXPORT_SYMBOL(mempool_alloc_slab);

void mempool_free_slab(void *element, void *pool_data)
{
    struct kmem_cache *mem = pool_data;
    kmem_cache_free(mem, element);
}
EXPORT_SYMBOL(mempool_free_slab);

static __always_inline void add_element(mempool_t *pool, void *element)
{
    BUG_ON(pool->curr_nr >= pool->min_nr);
    pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
    void *element = pool->elements[--pool->curr_nr];

    BUG_ON(pool->curr_nr < 0);
    return element;
}

/**
 * mempool_exit - exit a mempool initialized with mempool_init()
 * @pool:      pointer to the memory pool which was initialized with
 *             mempool_init().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 *
 * May be called on a zeroed but uninitialized mempool (i.e. allocated with
 * kzalloc()).
 */
void mempool_exit(mempool_t *pool)
{
    while (pool->curr_nr) {
        void *element = remove_element(pool);
        pool->free(element, pool->pool_data);
    }
    kfree(pool->elements);
    pool->elements = NULL;
}
EXPORT_SYMBOL(mempool_exit);

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn() function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 * Note: using __GFP_ZERO is not supported.
 *
 * Return: pointer to the allocated element or %NULL on error.
 */
void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
    void *element;
    unsigned long flags;
    //wait_queue_entry_t wait;
    gfp_t gfp_temp;

    VM_WARN_ON_ONCE(gfp_mask & __GFP_ZERO);
    might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

    gfp_mask |= __GFP_NOMEMALLOC;   /* don't allocate emergency reserves */
    gfp_mask |= __GFP_NORETRY;  /* don't loop in __alloc_pages */
    gfp_mask |= __GFP_NOWARN;   /* failures are OK */

    gfp_temp = gfp_mask & ~(__GFP_DIRECT_RECLAIM|__GFP_IO);

 repeat_alloc:

    element = pool->alloc(gfp_temp, pool->pool_data);
    if (likely(element != NULL))
        return element;

    panic("%s: END!\n", __func__);
}

int mempool_init_node(mempool_t *pool,
                      int min_nr,
                      mempool_alloc_t *alloc_fn,
                      mempool_free_t *free_fn,
                      void *pool_data,
                      gfp_t gfp_mask,
                      int node_id)
{
    spin_lock_init(&pool->lock);
    pool->min_nr    = min_nr;
    pool->pool_data = pool_data;
    pool->alloc = alloc_fn;
    pool->free  = free_fn;
    //init_waitqueue_head(&pool->wait);

    pool->elements =
        kmalloc_array_node(min_nr, sizeof(void *),
                           gfp_mask, node_id);
    if (!pool->elements)
        return -ENOMEM;

    /*
     * First pre-allocate the guaranteed number of buffers.
     */
    while (pool->curr_nr < pool->min_nr) {
        void *element;

        element = pool->alloc(gfp_mask, pool->pool_data);
        if (unlikely(!element)) {
            mempool_exit(pool);
            return -ENOMEM;
        }
        add_element(pool, element);
    }

    return 0;
}
EXPORT_SYMBOL(mempool_init_node);

/**
 * mempool_init - initialize a memory pool
 * @pool:      pointer to the memory pool that should be initialized
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * Like mempool_create(), but initializes the pool in (i.e. embedded in another
 * structure).
 *
 * Return: %0 on success, negative error code otherwise.
 */
int mempool_init(mempool_t *pool, int min_nr,
                 mempool_alloc_t *alloc_fn,
                 mempool_free_t *free_fn,
                 void *pool_data)
{
    return mempool_init_node(pool, min_nr, alloc_fn, free_fn,
                             pool_data, GFP_KERNEL, NUMA_NO_NODE);
}
EXPORT_SYMBOL(mempool_init);
