// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

/**
 * idr_alloc_u32() - Allocate an ID.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @nextid: Pointer to an ID.
 * @max: The maximum ID to allocate (inclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @nextid and @max.
 * Note that @max is inclusive whereas the @end parameter to idr_alloc()
 * is exclusive.  The new ID is assigned to @nextid before the pointer
 * is inserted into the IDR, so if @nextid points into the object pointed
 * to by @ptr, a concurrent lookup will not find an uninitialised ID.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: 0 if an ID was allocated, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.  If an error occurred,
 * @nextid is unchanged.
 */
int idr_alloc_u32(struct idr *idr, void *ptr, u32 *nextid,
                  unsigned long max, gfp_t gfp)
{
    struct radix_tree_iter iter;
    void __rcu **slot;
    unsigned int base = idr->idr_base;
    unsigned int id = *nextid;

    if (WARN_ON_ONCE(!(idr->idr_rt.xa_flags & ROOT_IS_IDR)))
        idr->idr_rt.xa_flags |= IDR_RT_MARKER;

    id = (id < base) ? 0 : id - base;
    radix_tree_iter_init(&iter, id);
    slot = idr_get_free(&idr->idr_rt, &iter, gfp, max - base);
    if (IS_ERR(slot))
        return PTR_ERR(slot);

    *nextid = iter.index + base;
    /* there is a memory barrier inside radix_tree_iter_replace() */
    radix_tree_iter_replace(&idr->idr_rt, &iter, slot, ptr);
    radix_tree_iter_tag_clear(&idr->idr_rt, &iter, IDR_FREE);

    return 0;
}
EXPORT_SYMBOL_GPL(idr_alloc_u32);

/**
 * idr_alloc_cyclic() - Allocate an ID cyclically.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @nextid and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 * The search for an unused ID will start at the last ID allocated and will
 * wrap around to @start if no free IDs are found before reaching @end.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{
    u32 id = idr->idr_next;
    int err, max = end > 0 ? end - 1 : INT_MAX;

    if ((int)id < start)
        id = start;

    err = idr_alloc_u32(idr, ptr, &id, max, gfp);
    if ((err == -ENOSPC) && (id > start)) {
        id = start;
        err = idr_alloc_u32(idr, ptr, &id, max, gfp);
    }
    if (err)
        return err;

    idr->idr_next = id + 1;
    return id;
}
EXPORT_SYMBOL(idr_alloc_cyclic);
