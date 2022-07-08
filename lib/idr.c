// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <linux/err.h>

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

/**
 * idr_alloc() - Allocate an ID.
 * @idr: IDR handle.
 * @ptr: Pointer to be associated with the new ID.
 * @start: The minimum ID (inclusive).
 * @end: The maximum ID (exclusive).
 * @gfp: Memory allocation flags.
 *
 * Allocates an unused ID in the range specified by @start and @end.  If
 * @end is <= 0, it is treated as one larger than %INT_MAX.  This allows
 * callers to use @start + N as @end as long as N is within integer range.
 *
 * The caller should provide their own locking to ensure that two
 * concurrent modifications to the IDR are not possible.  Read-only
 * accesses to the IDR may be done under the RCU read lock or may
 * exclude simultaneous writers.
 *
 * Return: The newly allocated ID, -ENOMEM if memory allocation failed,
 * or -ENOSPC if no free IDs could be found.
 */
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{
    u32 id = start;
    int ret;

    if (WARN_ON_ONCE(start < 0))
        return -EINVAL;

    ret = idr_alloc_u32(idr, ptr, &id, end > 0 ? end - 1 : INT_MAX, gfp);
    if (ret)
        return ret;

    return id;
}
EXPORT_SYMBOL_GPL(idr_alloc);

/**
 * idr_replace() - replace pointer for given ID.
 * @idr: IDR handle.
 * @ptr: New pointer to associate with the ID.
 * @id: ID to change.
 *
 * Replace the pointer registered with an ID and return the old value.
 * This function can be called under the RCU read lock concurrently with
 * idr_alloc() and idr_remove() (as long as the ID being removed is not
 * the one being replaced!).
 *
 * Returns: the old value on success.  %-ENOENT indicates that @id was not
 * found.  %-EINVAL indicates that @ptr was not valid.
 */
void *idr_replace(struct idr *idr, void *ptr, unsigned long id)
{
    struct radix_tree_node *node;
    void __rcu **slot = NULL;
    void *entry;

    id -= idr->idr_base;

    entry = __radix_tree_lookup(&idr->idr_rt, id, &node, &slot);
    if (!slot || radix_tree_tag_get(&idr->idr_rt, id, IDR_FREE))
        return ERR_PTR(-ENOENT);

    __radix_tree_replace(&idr->idr_rt, node, slot, ptr);

    return entry;
}
EXPORT_SYMBOL(idr_replace);

/**
 * ida_alloc_range() - Allocate an unused ID.
 * @ida: IDA handle.
 * @min: Lowest ID to allocate.
 * @max: Highest ID to allocate.
 * @gfp: Memory allocation flags.
 *
 * Allocate an ID between @min and @max, inclusive.  The allocated ID will
 * not exceed %INT_MAX, even if @max is larger.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 * Return: The allocated ID, or %-ENOMEM if memory could not be allocated,
 * or %-ENOSPC if there are no free IDs.
 */
int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max,
                    gfp_t gfp)
{
    XA_STATE(xas, &ida->xa, min / IDA_BITMAP_BITS);
    unsigned bit = min % IDA_BITMAP_BITS;
    unsigned long flags;
    struct ida_bitmap *bitmap, *alloc = NULL;

    if ((int)min < 0)
        return -ENOSPC;

    if ((int)max < 0)
        max = INT_MAX;

 retry:
    xas_lock_irqsave(&xas, flags);

 next:
    bitmap = xas_find_marked(&xas, max / IDA_BITMAP_BITS, XA_FREE_MARK);
    if (xas.xa_index > min / IDA_BITMAP_BITS)
        bit = 0;
    if (xas.xa_index * IDA_BITMAP_BITS + bit > max)
        goto nospc;

    if (xa_is_value(bitmap)) {
        unsigned long tmp = xa_to_value(bitmap);

        if (bit < BITS_PER_XA_VALUE) {
            bit = find_next_zero_bit(&tmp, BITS_PER_XA_VALUE, bit);
            if (xas.xa_index * IDA_BITMAP_BITS + bit > max)
                goto nospc;
            if (bit < BITS_PER_XA_VALUE) {
                tmp |= 1UL << bit;
                xas_store(&xas, xa_mk_value(tmp));
                goto out;
            }
        }

        panic("%s: xa for value NOT SUPPORTED!\n", __func__);
    }

    if (bitmap) {
        panic("%s: bitmap NOT NULL!\n");
    } else {
        if (bit < BITS_PER_XA_VALUE) {
            bitmap = xa_mk_value(1UL << bit);
        } else {
            bitmap = alloc;
            if (!bitmap)
                bitmap = kzalloc(sizeof(*bitmap), GFP_NOWAIT);
            if (!bitmap)
                goto alloc;
            __set_bit(bit, bitmap->bitmap);
        }
        xas_store(&xas, bitmap);
    }

 out:
    xas_unlock_irqrestore(&xas, flags);
    if (xas_nomem(&xas, gfp)) {
        xas.xa_index = min / IDA_BITMAP_BITS;
        bit = min % IDA_BITMAP_BITS;
        goto retry;
    }
    if (bitmap != alloc)
        kfree(alloc);
    if (xas_error(&xas))
        return xas_error(&xas);
    return xas.xa_index * IDA_BITMAP_BITS + bit;

 alloc:
    xas_unlock_irqrestore(&xas, flags);
    alloc = kzalloc(sizeof(*bitmap), gfp);
    if (!alloc)
        return -ENOMEM;
    xas_set(&xas, min / IDA_BITMAP_BITS);
    bit = min % IDA_BITMAP_BITS;
    goto retry;
 nospc:
    xas_unlock_irqrestore(&xas, flags);
    kfree(alloc);
    return -ENOSPC;
}
EXPORT_SYMBOL(ida_alloc_range);

/**
 * ida_free() - Release an allocated ID.
 * @ida: IDA handle.
 * @id: Previously allocated ID.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void ida_free(struct ida *ida, unsigned int id)
{
    XA_STATE(xas, &ida->xa, id / IDA_BITMAP_BITS);
    unsigned bit = id % IDA_BITMAP_BITS;
    struct ida_bitmap *bitmap;
    unsigned long flags;

    BUG_ON((int)id < 0);

    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(ida_free);

/**
 * ida_destroy() - Free all IDs.
 * @ida: IDA handle.
 *
 * Calling this function frees all IDs and releases all resources used
 * by an IDA.  When this call returns, the IDA is empty and can be reused
 * or freed.  If the IDA is already empty, there is no need to call this
 * function.
 *
 * Context: Any context. It is safe to call this function without
 * locking in your code.
 */
void ida_destroy(struct ida *ida)
{
    XA_STATE(xas, &ida->xa, 0);
    struct ida_bitmap *bitmap;
    unsigned long flags;

    panic("%s: END!\n", __func__);
#if 0
    xas_lock_irqsave(&xas, flags);
    xas_for_each(&xas, bitmap, ULONG_MAX) {
        if (!xa_is_value(bitmap))
            kfree(bitmap);
        xas_store(&xas, NULL);
    }
    xas_unlock_irqrestore(&xas, flags);
#endif
}
EXPORT_SYMBOL(ida_destroy);
