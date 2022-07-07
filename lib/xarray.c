// SPDX-License-Identifier: GPL-2.0+
/*
 * XArray implementation
 * Copyright (c) 2017-2018 Microsoft Corporation
 * Copyright (c) 2018-2020 Oracle
 * Author: Matthew Wilcox <willy@infradead.org>
 */

#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/xarray.h>

static void *set_bounds(struct xa_state *xas)
{
    xas->xa_node = XAS_BOUNDS;
    return NULL;
}

/*
 * Use this to calculate the maximum index that will need to be created
 * in order to add the entry described by @xas.  Because we cannot store a
 * multi-index entry at index 0, the calculation is a little more complex
 * than you might expect.
 */
static unsigned long xas_max(struct xa_state *xas)
{
    unsigned long max = xas->xa_index;
    return max;
}

static inline bool xa_zero_busy(const struct xarray *xa)
{
    return xa->xa_flags & XA_FLAGS_ZERO_BUSY;
}

/* The maximum index that can be contained in the array without expanding it */
static unsigned long max_index(void *entry)
{
    if (!xa_is_node(entry))
        return 0;
    return (XA_CHUNK_SIZE << xa_to_node(entry)->shift) - 1;
}

/**
 * xas_find_marked() - Find the next marked entry in the XArray.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 * @mark: Mark number to search for.
 *
 * If the @xas has not yet been walked to an entry, return the marked entry
 * which has an index >= xas.xa_index.  If it has been walked, the entry
 * currently being pointed at has been processed, and so we return the
 * first marked entry with an index > xas.xa_index.
 *
 * If no marked entry is found and the array is smaller than @max, @xas is
 * set to the bounds state and xas->xa_index is set to the smallest index
 * not yet in the array.  This allows @xas to be immediately passed to
 * xas_store().
 *
 * If no entry is found before @max is reached, @xas is set to the restart
 * state.
 *
 * Return: The entry, if found, otherwise %NULL.
 */
void *xas_find_marked(struct xa_state *xas, unsigned long max, xa_mark_t mark)
{
    bool advance = true;
    unsigned int offset;
    void *entry;

    if (xas_error(xas))
        return NULL;
    if (xas->xa_index > max)
        goto max;

    if (!xas->xa_node) {
        xas->xa_index = 1;
        goto out;
    } else if (xas_top(xas->xa_node)) {
        advance = false;
        entry = xa_head(xas->xa);
        xas->xa_node = NULL;
        if (xas->xa_index > max_index(entry))
            goto out;
        if (!xa_is_node(entry)) {
            if (xa_marked(xas->xa, mark))
                return entry;
            xas->xa_index = 1;
            goto out;
        }
        xas->xa_node = xa_to_node(entry);
        xas->xa_offset = xas->xa_index >> xas->xa_node->shift;
    }

    panic("%s: END!\n", __func__);

 out:
    if (xas->xa_index > max)
        goto max;
    return set_bounds(xas);
 max:
    xas->xa_node = XAS_RESTART;
    return NULL;
}
EXPORT_SYMBOL_GPL(xas_find_marked);

/* extracts the offset within this node from the index */
static unsigned int get_offset(unsigned long index, struct xa_node *node)
{
    return (index >> node->shift) & XA_CHUNK_MASK;
}

/*
 * Starts a walk.  If the @xas is already valid, we assume that it's on
 * the right path and just return where we've got to.  If we're in an
 * error state, return NULL.  If the index is outside the current scope
 * of the xarray, return NULL without changing @xas->xa_node.  Otherwise
 * set @xas->xa_node to NULL and return the current head of the array.
 */
static void *xas_start(struct xa_state *xas)
{
    void *entry;

    if (xas_valid(xas))
        return xas_reload(xas);
    if (xas_error(xas))
        return NULL;

    entry = xa_head(xas->xa);
    if (!xa_is_node(entry)) {
        if (xas->xa_index)
            return set_bounds(xas);
    } else {
        if ((xas->xa_index >> xa_to_node(entry)->shift) > XA_CHUNK_MASK)
            return set_bounds(xas);
    }

    xas->xa_node = NULL;
    return entry;
}

static void *xas_descend(struct xa_state *xas, struct xa_node *node)
{
    unsigned int offset = get_offset(xas->xa_index, node);
    void *entry = xa_entry(xas->xa, node, offset);

    xas->xa_node = node;
    if (xa_is_sibling(entry)) {
        panic("%s: NOT SUPPORT sibling for xarray!\n", __func__);
    }

    xas->xa_offset = offset;
    return entry;
}

/**
 * xas_load() - Load an entry from the XArray (advanced).
 * @xas: XArray operation state.
 *
 * Usually walks the @xas to the appropriate state to load the entry
 * stored at xa_index.  However, it will do nothing and return %NULL if
 * @xas is in an error state.  xas_load() will never expand the tree.
 *
 * If the xa_state is set up to operate on a multi-index entry, xas_load()
 * may return %NULL or an internal entry, even if there are entries
 * present within the range specified by @xas.
 *
 * Context: Any context.  The caller should hold the xa_lock or the RCU lock.
 * Return: Usually an entry in the XArray, but see description for exceptions.
 */
void *xas_load(struct xa_state *xas)
{
    void *entry = xas_start(xas);

    while (xa_is_node(entry)) {
        struct xa_node *node = xa_to_node(entry);

        if (xas->xa_shift > node->shift)
            break;
        entry = xas_descend(xas, node);
        if (node->shift == 0)
            break;
    }
    return entry;
}
EXPORT_SYMBOL_GPL(xas_load);

/*
 * xas_expand adds nodes to the head of the tree until it has reached
 * sufficient height to be able to contain @xas->xa_index
 */
static int xas_expand(struct xa_state *xas, void *head)
{
    struct xarray *xa = xas->xa;
    struct xa_node *node = NULL;
    unsigned int shift = 0;
    unsigned long max = xas_max(xas);

    if (!head) {
        if (max == 0)
            return 0;
        while ((max >> shift) >= XA_CHUNK_SIZE)
            shift += XA_CHUNK_SHIFT;
        return shift + XA_CHUNK_SHIFT;
    } else if (xa_is_node(head)) {
        node = xa_to_node(head);
        shift = node->shift + XA_CHUNK_SHIFT;
    }
    xas->xa_node = NULL;

    panic("%s: max(%lu) END!\n", __func__, max);
}

/*
 * xas_create() - Create a slot to store an entry in.
 * @xas: XArray operation state.
 * @allow_root: %true if we can store the entry in the root directly
 *
 * Most users will not need to call this function directly, as it is called
 * by xas_store().  It is useful for doing conditional store operations
 * (see the xa_cmpxchg() implementation for an example).
 *
 * Return: If the slot already existed, returns the contents of this slot.
 * If the slot was newly created, returns %NULL.  If it failed to create the
 * slot, returns %NULL and indicates the error in @xas.
 */
static void *xas_create(struct xa_state *xas, bool allow_root)
{
    struct xarray *xa = xas->xa;
    void *entry;
    void __rcu **slot;
    struct xa_node *node = xas->xa_node;
    int shift;
    unsigned int order = xas->xa_shift;

    if (xas_top(node)) {
        entry = xa_head_locked(xa);
        xas->xa_node = NULL;
        if (!entry && xa_zero_busy(xa))
            entry = XA_ZERO_ENTRY;
        shift = xas_expand(xas, entry);
        if (shift < 0)
            return NULL;
        if (!shift && !allow_root)
            shift = XA_CHUNK_SHIFT;
        entry = xa_head_locked(xa);
        slot = &xa->xa_head;
    } else if (xas_error(xas)) {
        return NULL;
    } else if (node) {
        unsigned int offset = xas->xa_offset;

        shift = node->shift;
        entry = xa_entry_locked(xa, node, offset);
        slot = &node->slots[offset];
    } else {
        shift = 0;
        entry = xa_head_locked(xa);
        slot = &xa->xa_head;
    }

    panic("%s: allow_root(%d) END!\n", __func__, allow_root);
}

/**
 * xas_store() - Store this entry in the XArray.
 * @xas: XArray operation state.
 * @entry: New entry.
 *
 * If @xas is operating on a multi-index entry, the entry returned by this
 * function is essentially meaningless (it may be an internal entry or it
 * may be %NULL, even if there are non-NULL entries at some of the indices
 * covered by the range).  This is not a problem for any current users,
 * and can be changed if needed.
 *
 * Return: The old entry at this index.
 */
void *xas_store(struct xa_state *xas, void *entry)
{
    struct xa_node *node;
    void __rcu **slot = &xas->xa->xa_head;
    unsigned int offset, max;
    int count = 0;
    int values = 0;
    void *first, *next;
    bool value = xa_is_value(entry);

    if (entry) {
        bool allow_root = !xa_is_node(entry) && !xa_is_zero(entry);
        first = xas_create(xas, allow_root);
    } else {
        first = xas_load(xas);
    }

    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(xas_store);
