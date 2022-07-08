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

extern struct kmem_cache *radix_tree_node_cachep;

extern void radix_tree_node_rcu_free(struct rcu_head *head);

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

static inline bool xa_track_free(const struct xarray *xa)
{
    return xa->xa_flags & XA_FLAGS_TRACK_FREE;
}

/* The maximum index that can be contained in the array without expanding it */
static unsigned long max_index(void *entry)
{
    if (!xa_is_node(entry))
        return 0;
    return (XA_CHUNK_SIZE << xa_to_node(entry)->shift) - 1;
}

static inline unsigned long *node_marks(struct xa_node *node, xa_mark_t mark)
{
    return node->marks[(__force unsigned)mark];
}

static inline void node_mark_all(struct xa_node *node, xa_mark_t mark)
{
    bitmap_fill(node_marks(node, mark), XA_CHUNK_SIZE);
}

/* returns true if the bit was set */
static inline bool node_set_mark(struct xa_node *node, unsigned int offset,
                                 xa_mark_t mark)
{
    return __test_and_set_bit(offset, node_marks(node, mark));
}

/* returns true if the bit was set */
static inline bool node_clear_mark(struct xa_node *node, unsigned int offset,
                                   xa_mark_t mark)
{
    return __test_and_clear_bit(offset, node_marks(node, mark));
}

static inline bool node_any_mark(struct xa_node *node, xa_mark_t mark)
{
    return !bitmap_empty(node_marks(node, mark), XA_CHUNK_SIZE);
}

static inline void xa_mark_set(struct xarray *xa, xa_mark_t mark)
{
    if (!(xa->xa_flags & XA_FLAGS_MARK(mark)))
        xa->xa_flags |= XA_FLAGS_MARK(mark);
}

static inline void xa_mark_clear(struct xarray *xa, xa_mark_t mark)
{
    if (xa->xa_flags & XA_FLAGS_MARK(mark))
        xa->xa_flags &= ~(XA_FLAGS_MARK(mark));
}

#define mark_inc(mark) do { \
    mark = (__force xa_mark_t)((__force unsigned)(mark) + 1); \
} while (0)

/*
 * xas_squash_marks() - Merge all marks to the first entry
 * @xas: Array operation state.
 *
 * Set a mark on the first entry if any entry has it set.  Clear marks on
 * all sibling entries.
 */
static void xas_squash_marks(const struct xa_state *xas)
{
    unsigned int mark = 0;
    unsigned int limit = xas->xa_offset + xas->xa_sibs + 1;

    if (!xas->xa_sibs)
        return;

    panic("%s: END!\n", __func__);
}

/**
 * xas_set_mark() - Sets the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Sets the specified mark on this entry, and walks up the tree setting it
 * on all the ancestor entries.  Does nothing if @xas has not been walked to
 * an entry, or is in an error state.
 */
void xas_set_mark(const struct xa_state *xas, xa_mark_t mark)
{
    struct xa_node *node = xas->xa_node;
    unsigned int offset = xas->xa_offset;

    if (xas_invalid(xas))
        return;

    while (node) {
        if (node_set_mark(node, offset, mark))
            return;
        offset = node->offset;
        node = xa_parent_locked(xas->xa, node);
    }

    if (!xa_marked(xas->xa, mark))
        xa_mark_set(xas->xa, mark);
}
EXPORT_SYMBOL_GPL(xas_set_mark);

/**
 * xas_clear_mark() - Clears the mark on this entry and its parents.
 * @xas: XArray operation state.
 * @mark: Mark number.
 *
 * Clears the specified mark on this entry, and walks back to the head
 * attempting to clear it on all the ancestor entries.  Does nothing if
 * @xas has not been walked to an entry, or is in an error state.
 */
void xas_clear_mark(const struct xa_state *xas, xa_mark_t mark)
{
    struct xa_node *node = xas->xa_node;
    unsigned int offset = xas->xa_offset;

    if (xas_invalid(xas))
        return;

    while (node) {
        if (!node_clear_mark(node, offset, mark))
            return;
        if (node_any_mark(node, mark))
            return;

        offset = node->offset;
        node = xa_parent_locked(xas->xa, node);
    }

    if (xa_marked(xas->xa, mark))
        xa_mark_clear(xas->xa, mark);
}
EXPORT_SYMBOL_GPL(xas_clear_mark);

/**
 * xas_init_marks() - Initialise all marks for the entry
 * @xas: Array operations state.
 *
 * Initialise all marks for the entry specified by @xas.  If we're tracking
 * free entries with a mark, we need to set it on all entries.  All other
 * marks are cleared.
 *
 * This implementation is not as efficient as it could be; we may walk
 * up the tree multiple times.
 */
void xas_init_marks(const struct xa_state *xas)
{
    xa_mark_t mark = 0;

    for (;;) {
        if (xa_track_free(xas->xa) && mark == XA_FREE_MARK)
            xas_set_mark(xas, mark);
        else
            xas_clear_mark(xas, mark);
        if (mark == XA_MARK_MAX)
            break;
        mark_inc(mark);
    }
}
EXPORT_SYMBOL_GPL(xas_init_marks);

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

static void *xas_alloc(struct xa_state *xas, unsigned int shift)
{
    panic("%s: shift(%lu) END!\n", __func__, shift);
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

    while (shift > order) {
        shift -= XA_CHUNK_SHIFT;
        if (!entry) {
            node = xas_alloc(xas, shift);
            if (!node)
                break;
            if (xa_track_free(xa))
                node_mark_all(node, XA_FREE_MARK);
            rcu_assign_pointer(*slot, xa_mk_node(node));
        } else if (xa_is_node(entry)) {
            node = xa_to_node(entry);
        } else {
            break;
        }
        entry = xas_descend(xas, node);
        slot = &node->slots[xas->xa_offset];
    }

    return entry;
}

/**
 * xas_free_nodes() - Free this node and all nodes that it references
 * @xas: Array operation state.
 * @top: Node to free
 *
 * This node has been removed from the tree.  We must now free it and all
 * of its subnodes.  There may be RCU walkers with references into the tree,
 * so we must replace all entries with retry markers.
 */
static void xas_free_nodes(struct xa_state *xas, struct xa_node *top)
{
    unsigned int offset = 0;
    struct xa_node *node = top;

    panic("%s: END!\n", __func__);
}

static void xas_update(struct xa_state *xas, struct xa_node *node)
{
    if (xas->xa_update)
        xas->xa_update(node);
    else
        XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
}

/*
 * xas_delete_node() - Attempt to delete an xa_node
 * @xas: Array operation state.
 *
 * Attempts to delete the @xas->xa_node.  This will fail if xa->node has
 * a non-zero reference count.
 */
static void xas_delete_node(struct xa_state *xas)
{
    struct xa_node *node = xas->xa_node;

    panic("%s: END!\n", __func__);
}

static void update_node(struct xa_state *xas, struct xa_node *node,
                        int count, int values)
{
    if (!node || (!count && !values))
        return;

    node->count += count;
    node->nr_values += values;
    XA_NODE_BUG_ON(node, node->count > XA_CHUNK_SIZE);
    XA_NODE_BUG_ON(node, node->nr_values > XA_CHUNK_SIZE);
    xas_update(xas, node);
    if (count < 0)
        xas_delete_node(xas);
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

    if (xas_invalid(xas))
        return first;
    node = xas->xa_node;
    if (node && (xas->xa_shift < node->shift))
        xas->xa_sibs = 0;
    if ((first == entry) && !xas->xa_sibs)
        return first;

    next = first;
    offset = xas->xa_offset;
    max = xas->xa_offset + xas->xa_sibs;
    if (node) {
        slot = &node->slots[offset];
        if (xas->xa_sibs)
            xas_squash_marks(xas);
    }
    if (!entry)
        xas_init_marks(xas);

    for (;;) {
        /*
         * Must clear the marks before setting the entry to NULL,
         * otherwise xas_for_each_marked may find a NULL entry and
         * stop early.  rcu_assign_pointer contains a release barrier
         * so the mark clearing will appear to happen before the
         * entry is set to NULL.
         */
        rcu_assign_pointer(*slot, entry);
        if (xa_is_node(next) && (!node || node->shift))
            xas_free_nodes(xas, xa_to_node(next));
        if (!node)
            break;

        panic("%s: NOT implementation entry(%lx)!\n", __func__, entry);
    }

    update_node(xas, node, count, values);
    return first;
}
EXPORT_SYMBOL_GPL(xas_store);

/*
 * xas_destroy() - Free any resources allocated during the XArray operation.
 * @xas: XArray operation state.
 *
 * This function is now internal-only.
 */
static void xas_destroy(struct xa_state *xas)
{
    struct xa_node *next, *node = xas->xa_alloc;

    while (node) {
        XA_NODE_BUG_ON(node, !list_empty(&node->private_list));
        next = rcu_dereference_raw(node->parent);
        radix_tree_node_rcu_free(&node->rcu_head);
        xas->xa_alloc = node = next;
    }
}

/**
 * xas_nomem() - Allocate memory if needed.
 * @xas: XArray operation state.
 * @gfp: Memory allocation flags.
 *
 * If we need to add new nodes to the XArray, we try to allocate memory
 * with GFP_NOWAIT while holding the lock, which will usually succeed.
 * If it fails, @xas is flagged as needing memory to continue.  The caller
 * should drop the lock and call xas_nomem().  If xas_nomem() succeeds,
 * the caller should retry the operation.
 *
 * Forward progress is guaranteed as one node is allocated here and
 * stored in the xa_state where it will be found by xas_alloc().  More
 * nodes will likely be found in the slab allocator, but we do not tie
 * them up here.
 *
 * Return: true if memory was needed, and was successfully allocated.
 */
bool xas_nomem(struct xa_state *xas, gfp_t gfp)
{
    if (xas->xa_node != XA_ERROR(-ENOMEM)) {
        xas_destroy(xas);
        return false;
    }
    if (xas->xa->xa_flags & XA_FLAGS_ACCOUNT)
        gfp |= __GFP_ACCOUNT;
    xas->xa_alloc = kmem_cache_alloc_lru(radix_tree_node_cachep, xas->xa_lru, gfp);
    if (!xas->xa_alloc)
        return false;
    xas->xa_alloc->parent = NULL;
    XA_NODE_BUG_ON(xas->xa_alloc, !list_empty(&xas->xa_alloc->private_list));
    xas->xa_node = XAS_RESTART;
    return true;
}
EXPORT_SYMBOL_GPL(xas_nomem);
