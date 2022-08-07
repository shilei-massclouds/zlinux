/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_XARRAY_H
#define _LINUX_XARRAY_H
/*
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */

#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/err.h>

struct xa_node;

#define XA_BUG_ON(xa, x)        do { } while (0)
#define XA_NODE_BUG_ON(node, x) do { } while (0)

/*
 * The bottom two bits of the entry determine how the XArray interprets
 * the contents:
 *
 * 00: Pointer entry
 * 10: Internal entry
 * x1: Value entry or tagged pointer
 *
 * Attempting to store internal entries in the XArray is a bug.
 *
 * Most internal entries are pointers to the next node in the tree.
 * The following internal entries have a special meaning:
 *
 * 0-62: Sibling entries
 * 256: Retry entry
 * 257: Zero entry
 *
 * Errors are also represented as internal entries, but use the negative
 * space (-4094 to -2).  They're never stored in the slots array; only
 * returned by the normal API.
 */

#define BITS_PER_XA_VALUE   (BITS_PER_LONG - 1)

/**
 * xas_for_each() - Iterate over a range of an XArray.
 * @xas: XArray operation state.
 * @entry: Entry retrieved from the array.
 * @max: Maximum index to retrieve from array.
 *
 * The loop body will be executed for each entry present in the xarray
 * between the current xas position and @max.  @entry will be set to
 * the entry retrieved from the xarray.  It is safe to delete entries
 * from the array in the loop body.  You should hold either the RCU lock
 * or the xa_lock while iterating.  If you need to drop the lock, call
 * xas_pause() first.
 */
#define xas_for_each(xas, entry, max) \
    for (entry = xas_find(xas, max); entry; \
         entry = xas_next_entry(xas, max))

/* True if the pointer is something other than a node */
static inline bool xas_not_node(struct xa_node *node)
{
    return ((unsigned long)node & 3) || !node;
}

/**
 * xa_mk_value() - Create an XArray entry from an integer.
 * @v: Value to store in XArray.
 *
 * Context: Any context.
 * Return: An entry suitable for storing in the XArray.
 */
static inline void *xa_mk_value(unsigned long v)
{
    WARN_ON((long)v < 0);
    return (void *)((v << 1) | 1);
}

typedef unsigned __bitwise xa_mark_t;
#define XA_MARK_0       ((__force xa_mark_t)0U)
#define XA_MARK_1       ((__force xa_mark_t)1U)
#define XA_MARK_2       ((__force xa_mark_t)2U)
#define XA_PRESENT      ((__force xa_mark_t)8U)
#define XA_MARK_MAX     XA_MARK_2
#define XA_FREE_MARK    XA_MARK_0

enum xa_lock_type {
    XA_LOCK_IRQ = 1,
    XA_LOCK_BH = 2,
};

/*
 * Values for xa_flags.  The radix tree stores its GFP flags in the xa_flags,
 * and we remain compatible with that.
 */
#define XA_FLAGS_LOCK_IRQ   ((__force gfp_t)XA_LOCK_IRQ)
#define XA_FLAGS_LOCK_BH    ((__force gfp_t)XA_LOCK_BH)
#define XA_FLAGS_TRACK_FREE ((__force gfp_t)4U)
#define XA_FLAGS_ZERO_BUSY  ((__force gfp_t)8U)
#define XA_FLAGS_ALLOC_WRAPPED  ((__force gfp_t)16U)
#define XA_FLAGS_ACCOUNT    ((__force gfp_t)32U)

#define XA_FLAGS_MARK(mark) \
    ((__force gfp_t)((1U << __GFP_BITS_SHIFT) << (__force unsigned)(mark)))

/* ALLOC is for a normal 0-based alloc.  ALLOC1 is for an 1-based alloc */
#define XA_FLAGS_ALLOC  (XA_FLAGS_TRACK_FREE | XA_FLAGS_MARK(XA_FREE_MARK))
#define XA_FLAGS_ALLOC1 (XA_FLAGS_TRACK_FREE | XA_FLAGS_ZERO_BUSY)

/**
 * struct xarray - The anchor of the XArray.
 * @xa_lock: Lock that protects the contents of the XArray.
 *
 * To use the xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to an @xa_node.
 */
struct xarray {
    spinlock_t  xa_lock;
/* private: The rest of the data structure is not to be used directly. */
    gfp_t       xa_flags;
    void __rcu *xa_head;
};

/*
 * The xarray is constructed out of a set of 'chunks' of pointers.  Choosing
 * the best chunk size requires some tradeoffs.  A power of two recommends
 * itself so that we can walk the tree based purely on shifts and masks.
 * Generally, the larger the better; as the number of slots per level of the
 * tree increases, the less tall the tree needs to be.  But that needs to be
 * balanced against the memory consumption of each node.  On a 64-bit system,
 * xa_node is currently 576 bytes, and we get 7 of them per 4kB page.  If we
 * doubled the number of slots per node, we'd get only 3 nodes per 4kB page.
 */
#ifndef XA_CHUNK_SHIFT
#define XA_CHUNK_SHIFT      (6)
#endif
#define XA_CHUNK_SIZE       (1UL << XA_CHUNK_SHIFT)
#define XA_CHUNK_MASK       (XA_CHUNK_SIZE - 1)
#define XA_MAX_MARKS        3
#define XA_MARK_LONGS       DIV_ROUND_UP(XA_CHUNK_SIZE, BITS_PER_LONG)

/*
 * xa_mk_internal() - Create an internal entry.
 * @v: Value to turn into an internal entry.
 *
 * Internal entries are used for a number of purposes.  Entries 0-255 are
 * used for sibling entries (only 0-62 are used by the current code).  256
 * is used for the retry entry.  257 is used for the reserved / zero entry.
 * Negative internal entries are used to represent errnos.  Node pointers
 * are also tagged as internal entries in some situations.
 *
 * Context: Any context.
 * Return: An XArray internal entry corresponding to this value.
 */
static inline void *xa_mk_internal(unsigned long v)
{
    return (void *)((v << 2) | 2);
}

#define XA_RETRY_ENTRY      xa_mk_internal(256)

/*
 * @count is the count of every non-NULL element in the ->slots array
 * whether that is a value entry, a retry entry, a user pointer,
 * a sibling entry or a pointer to the next level of the tree.
 * @nr_values is the count of every element in ->slots which is
 * either a value entry or a sibling of a value entry.
 */
struct xa_node {
    unsigned char   shift;      /* Bits remaining in each slot */
    unsigned char   offset;     /* Slot offset in parent */
    unsigned char   count;      /* Total entry count */
    unsigned char   nr_values;  /* Value entry count */
    struct xa_node __rcu *parent;   /* NULL at top of tree */
    struct xarray   *array;     /* The array we belong to */
    union {
        struct list_head private_list;  /* For tree user */
        struct rcu_head rcu_head;   /* Used when freeing node */
    };
    void __rcu  *slots[XA_CHUNK_SIZE];
    union {
        unsigned long   tags[XA_MAX_MARKS][XA_MARK_LONGS];
        unsigned long   marks[XA_MAX_MARKS][XA_MARK_LONGS];
    };
};

/**
 * typedef xa_update_node_t - A callback function from the XArray.
 * @node: The node which is being processed
 *
 * This function is called every time the XArray updates the count of
 * present and value entries in a node.  It allows advanced users to
 * maintain the private_list in the node.
 *
 * Context: The xa_lock is held and interrupts may be disabled.
 *      Implementations should not drop the xa_lock, nor re-enable
 *      interrupts.
 */
typedef void (*xa_update_node_t)(struct xa_node *node);

void xa_delete_node(struct xa_node *, xa_update_node_t);

/*
 * The xa_state is opaque to its users.  It contains various different pieces
 * of state involved in the current operation on the XArray.  It should be
 * declared on the stack and passed between the various internal routines.
 * The various elements in it should not be accessed directly, but only
 * through the provided accessor functions.  The below documentation is for
 * the benefit of those working on the code, not for users of the XArray.
 *
 * @xa_node usually points to the xa_node containing the slot we're operating
 * on (and @xa_offset is the offset in the slots array).  If there is a
 * single entry in the array at index 0, there are no allocated xa_nodes to
 * point to, and so we store %NULL in @xa_node.  @xa_node is set to
 * the value %XAS_RESTART if the xa_state is not walked to the correct
 * position in the tree of nodes for this operation.  If an error occurs
 * during an operation, it is set to an %XAS_ERROR value.  If we run off the
 * end of the allocated nodes, it is set to %XAS_BOUNDS.
 */
struct xa_state {
    struct xarray *xa;
    unsigned long xa_index;
    unsigned char xa_shift;
    unsigned char xa_sibs;
    unsigned char xa_offset;
    unsigned char xa_pad;       /* Helps gcc generate better code */
    struct xa_node *xa_node;
    struct xa_node *xa_alloc;
    xa_update_node_t xa_update;
    struct list_lru *xa_lru;
};

#define XARRAY_INIT(name, flags) {                      \
    .xa_lock    = __SPIN_LOCK_UNLOCKED(name.xa_lock),   \
    .xa_flags   = flags,                                \
    .xa_head    = NULL,                                 \
}

/**
 * DEFINE_XARRAY_FLAGS() - Define an XArray with custom flags.
 * @name: A string that names your XArray.
 * @flags: XA_FLAG values.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name and flags.  It is
 * equivalent to calling xa_init_flags() on the array, but it does the
 * initialisation at compiletime instead of runtime.
 */
#define DEFINE_XARRAY_FLAGS(name, flags)                \
    struct xarray name = XARRAY_INIT(name, flags)

/**
 * DEFINE_XARRAY() - Define an XArray.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name.  It is equivalent
 * to calling xa_init() on the array, but it does the initialisation at
 * compiletime instead of runtime.
 */
#define DEFINE_XARRAY(name) DEFINE_XARRAY_FLAGS(name, 0)

/*
 * We encode errnos in the xas->xa_node.  If an error has happened, we need to
 * drop the lock to fix it, and once we've done so the xa_state is invalid.
 */
#define XA_ERROR(errno) ((struct xa_node *)(((unsigned long)errno << 2) | 2UL))
#define XAS_BOUNDS      ((struct xa_node *)1UL)
#define XAS_RESTART     ((struct xa_node *)3UL)

#define __XA_STATE(array, index, shift, sibs) { \
    .xa = array,                    \
    .xa_index = index,              \
    .xa_shift = shift,              \
    .xa_sibs = sibs,                \
    .xa_offset = 0,                 \
    .xa_pad = 0,                    \
    .xa_node = XAS_RESTART,         \
    .xa_alloc = NULL,               \
    .xa_update = NULL,              \
    .xa_lru = NULL,                 \
}

/**
 * XA_STATE() - Declare an XArray operation state.
 * @name: Name of this operation state (usually xas).
 * @array: Array to operate on.
 * @index: Initial index of interest.
 *
 * Declare and initialise an xa_state on the stack.
 */
#define XA_STATE(name, array, index)                \
    struct xa_state name = __XA_STATE(array, index, 0, 0)

/**
 * xa_init_flags() - Initialise an empty XArray with flags.
 * @xa: XArray.
 * @flags: XA_FLAG values.
 *
 * If you need to initialise an XArray with special flags (eg you need
 * to take the lock from interrupt context), use this function instead
 * of xa_init().
 *
 * Context: Any context.
 */
static inline void xa_init_flags(struct xarray *xa, gfp_t flags)
{
    spin_lock_init(&xa->xa_lock);
    xa->xa_flags = flags;
    xa->xa_head = NULL;
}

/**
 * xa_is_value() - Determine if an entry is a value.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: True if the entry is a value, false if it is a pointer.
 */
static inline bool xa_is_value(const void *entry)
{
    return (unsigned long)entry & 1;
}

#define xa_lock_irq(xa)     spin_lock_irq(&(xa)->xa_lock)
#define xa_unlock_irq(xa)   spin_unlock_irq(&(xa)->xa_lock)

#define xa_lock_bh(xa)      spin_lock_bh(&(xa)->xa_lock)
#define xa_unlock_bh(xa)    spin_unlock_bh(&(xa)->xa_lock)

#define xa_lock_irqsave(xa, flags) \
    spin_lock_irqsave(&(xa)->xa_lock, flags)

#define xa_unlock_irqrestore(xa, flags) \
    spin_unlock_irqrestore(&(xa)->xa_lock, flags)

#define xas_lock_irqsave(xas, flags) \
    xa_lock_irqsave((xas)->xa, flags)

#define xas_unlock_irqrestore(xas, flags) \
    xa_unlock_irqrestore((xas)->xa, flags)

#define xas_lock_irq(xas)   xa_lock_irq((xas)->xa)
#define xas_unlock_irq(xas) xa_unlock_irq((xas)->xa)

#define xas_lock(xas)       xa_lock((xas)->xa)
#define xas_unlock(xas)     xa_unlock((xas)->xa)
#define xas_lock_bh(xas)    xa_lock_bh((xas)->xa)
#define xas_unlock_bh(xas)  xa_unlock_bh((xas)->xa)

void *xas_find_marked(struct xa_state *, unsigned long max, xa_mark_t);

/**
 * xas_set() - Set up XArray operation state for a different index.
 * @xas: XArray operation state.
 * @index: New index into the XArray.
 *
 * Move the operation state to refer to a different index.  This will
 * have the effect of starting a walk from the top; see xas_next()
 * to move to an adjacent index.
 */
static inline void xas_set(struct xa_state *xas, unsigned long index)
{
    xas->xa_index = index;
    xas->xa_node = XAS_RESTART;
}

/*
 * xa_to_internal() - Extract the value from an internal entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value which was stored in the internal entry.
 */
static inline unsigned long xa_to_internal(const void *entry)
{
    return (unsigned long)entry >> 2;
}

/*
 * xa_is_internal() - Is the entry an internal entry?
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: %true if the entry is an internal entry.
 */
static inline bool xa_is_internal(const void *entry)
{
    return ((unsigned long)entry & 3) == 2;
}

#define XA_ZERO_ENTRY   xa_mk_internal(257)

/**
 * xa_is_zero() - Is the entry a zero entry?
 * @entry: Entry retrieved from the XArray
 *
 * The normal API will return NULL as the contents of a slot containing
 * a zero entry.  You can only see zero entries by using the advanced API.
 *
 * Return: %true if the entry is a zero entry.
 */
static inline bool xa_is_zero(const void *entry)
{
    return unlikely(entry == XA_ZERO_ENTRY);
}

/**
 * xa_is_err() - Report whether an XArray operation returned an error
 * @entry: Result from calling an XArray function
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special value indicating an error.  This function tells you
 * whether an error occurred; xa_err() tells you which error occurred.
 *
 * Context: Any context.
 * Return: %true if the entry indicates an error.
 */
static inline bool xa_is_err(const void *entry)
{
    return unlikely(xa_is_internal(entry) &&
                    entry >= xa_mk_internal(-MAX_ERRNO));
}

/**
 * xa_err() - Turn an XArray result into an errno.
 * @entry: Result from calling an XArray function.
 *
 * If an XArray operation cannot complete an operation, it will return
 * a special pointer value which encodes an errno.  This function extracts
 * the errno from the pointer value, or returns 0 if the pointer does not
 * represent an errno.
 *
 * Context: Any context.
 * Return: A negative errno or 0.
 */
static inline int xa_err(void *entry)
{
    /* xa_to_internal() would not do sign extension. */
    if (xa_is_err(entry))
        return (long)entry >> 2;
    return 0;
}

/**
 * xas_error() - Return an errno stored in the xa_state.
 * @xas: XArray operation state.
 *
 * Return: 0 if no error has been noted.  A negative errno if one has.
 */
static inline int xas_error(const struct xa_state *xas)
{
    return xa_err(xas->xa_node);
}

/* Private */
static inline struct xa_node *xa_to_node(const void *entry)
{
    return (struct xa_node *)((unsigned long)entry - 2);
}

/* Private */
static inline bool xa_is_node(const void *entry)
{
    return xa_is_internal(entry) && (unsigned long)entry > 4096;
}

/* Private */
static inline void *xa_head(const struct xarray *xa)
{
    return rcu_dereference_check(xa->xa_head);
}

/* Private */
static inline void *xa_mk_sibling(unsigned int offset)
{
    return xa_mk_internal(offset);
}

/* Private */
static inline void *xa_entry(const struct xarray *xa,
                const struct xa_node *node, unsigned int offset)
{
    XA_NODE_BUG_ON(node, offset >= XA_CHUNK_SIZE);
    return rcu_dereference_check(node->slots[offset]);
}

/* True if the node represents head-of-tree, RESTART or BOUNDS */
static inline bool xas_top(struct xa_node *node)
{
    return node <= XAS_RESTART;
}

/**
 * xa_marked() - Inquire whether any entry in this array has a mark set
 * @xa: Array
 * @mark: Mark value
 *
 * Context: Any context.
 * Return: %true if any entry has this mark set.
 */
static inline bool xa_marked(const struct xarray *xa, xa_mark_t mark)
{
    return xa->xa_flags & XA_FLAGS_MARK(mark);
}

void *xas_load(struct xa_state *);
void *xas_store(struct xa_state *, void *entry);
void *xas_find(struct xa_state *, unsigned long max);
void *xas_find_conflict(struct xa_state *);

/**
 * xa_is_sibling() - Is the entry a sibling entry?
 * @entry: Entry retrieved from the XArray
 *
 * Return: %true if the entry is a sibling entry.
 */
static inline bool xa_is_sibling(const void *entry)
{
    return false;
}

/**
 * xas_invalid() - Is the xas in a retry or error state?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas cannot be used for operations.
 */
static inline bool xas_invalid(const struct xa_state *xas)
{
    return (unsigned long)xas->xa_node & 3;
}

/**
 * xas_valid() - Is the xas a valid cursor into the array?
 * @xas: XArray operation state.
 *
 * Return: %true if the xas can be used for operations.
 */
static inline bool xas_valid(const struct xa_state *xas)
{
    return !xas_invalid(xas);
}

/**
 * xas_reload() - Refetch an entry from the xarray.
 * @xas: XArray operation state.
 *
 * Use this function to check that a previously loaded entry still has
 * the same value.  This is useful for the lockless pagecache lookup where
 * we walk the array with only the RCU lock to protect us, lock the page,
 * then check that the page hasn't moved since we looked it up.
 *
 * The caller guarantees that @xas is still valid.  If it may be in an
 * error or restart state, call xas_load() instead.
 *
 * Return: The entry at this location in the xarray.
 */
static inline void *xas_reload(struct xa_state *xas)
{
    struct xa_node *node = xas->xa_node;
    char offset;

    if (!node)
        return xa_head(xas->xa);

    offset = xas->xa_offset;
    return xa_entry(xas->xa, node, offset);
}

/* Private */
static inline void *xa_head_locked(const struct xarray *xa)
{
    return rcu_dereference_protected(xa->xa_head);
}

/* Private */
static inline void *xa_entry_locked(const struct xarray *xa,
                const struct xa_node *node, unsigned int offset)
{
    XA_NODE_BUG_ON(node, offset >= XA_CHUNK_SIZE);
    return rcu_dereference_protected(node->slots[offset]);
}

/* Private */
static inline void *xa_mk_node(const struct xa_node *node)
{
    return (void *)((unsigned long)node | 2);
}

/* Private */
static inline struct xa_node *
xa_parent_locked(const struct xarray *xa, const struct xa_node *node)
{
    return rcu_dereference_protected(node->parent);
}

bool xas_nomem(struct xa_state *, gfp_t);

/**
 * xa_to_value() - Get value stored in an XArray entry.
 * @entry: XArray entry.
 *
 * Context: Any context.
 * Return: The value stored in the XArray entry.
 */
static inline unsigned long xa_to_value(const void *entry)
{
    return (unsigned long)entry >> 1;
}

#define xa_lock(xa)     spin_lock(&(xa)->xa_lock)
#define xa_unlock(xa)   spin_unlock(&(xa)->xa_lock)

/**
 * xa_init() - Initialise an empty XArray.
 * @xa: XArray.
 *
 * An empty XArray is full of NULL entries.
 *
 * Context: Any context.
 */
static inline void xa_init(struct xarray *xa)
{
    xa_init_flags(xa, 0);
}

int __must_check __xa_insert(struct xarray *, unsigned long index,
                             void *entry, gfp_t);

/**
 * xa_insert() - Store this entry in the XArray unless another entry is
 *          already present.
 * @xa: XArray.
 * @index: Index into array.
 * @entry: New entry.
 * @gfp: Memory allocation flags.
 *
 * Inserting a NULL entry will store a reserved entry (like xa_reserve())
 * if no entry is present.  Inserting will fail if a reserved entry is
 * present, even though loading from this index will return NULL.
 *
 * Context: Any context.  Takes and releases the xa_lock.  May sleep if
 * the @gfp flags permit.
 * Return: 0 if the store succeeded.  -EBUSY if another entry was present.
 * -ENOMEM if memory could not be allocated.
 */
static inline int __must_check
xa_insert(struct xarray *xa, unsigned long index, void *entry, gfp_t gfp)
{
    int err;

    xa_lock(xa);
    err = __xa_insert(xa, index, entry, gfp);
    xa_unlock(xa);

    return err;
}

/**
 * xa_is_advanced() - Is the entry only permitted for the advanced API?
 * @entry: Entry to be stored in the XArray.
 *
 * Return: %true if the entry cannot be stored by the normal API.
 */
static inline bool xa_is_advanced(const void *entry)
{
    return xa_is_internal(entry) && (entry <= XA_RETRY_ENTRY);
}

/**
 * xas_set_err() - Note an error in the xa_state.
 * @xas: XArray operation state.
 * @err: Negative error number.
 *
 * Only call this function with a negative @err; zero or positive errors
 * will probably not behave the way you think they should.  If you want
 * to clear the error from an xa_state, use xas_reset().
 */
static inline void xas_set_err(struct xa_state *xas, long err)
{
    xas->xa_node = XA_ERROR(err);
}

bool xas_nomem(struct xa_state *, gfp_t);

void *xa_find(struct xarray *xa, unsigned long *index,
              unsigned long max, xa_mark_t) __attribute__((nonnull(2)));
void *xa_find_after(struct xarray *xa, unsigned long *index,
                    unsigned long max, xa_mark_t) __attribute__((nonnull(2)));

/**
 * xa_for_each_range() - Iterate over a portion of an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 * @start: First index to retrieve from array.
 * @last: Last index to retrieve from array.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  You may modify @index during the iteration if you
 * want to skip or reprocess indices.  It is safe to modify the array
 * during the iteration.  At the end of the iteration, @entry will be set
 * to NULL and @index will have a value less than or equal to max.
 *
 * xa_for_each_range() is O(n.log(n)) while xas_for_each() is O(n).  You have
 * to handle your own locking with xas_for_each(), and if you have to unlock
 * after each iteration, it will also end up being O(n.log(n)).
 * xa_for_each_range() will spin if it hits a retry entry; if you intend to
 * see retry entries, you should use the xas_for_each() iterator instead.
 * The xas_for_each() iterator will expand into more inline code than
 * xa_for_each_range().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define xa_for_each_range(xa, index, entry, start, last)    \
    for (index = start,                                     \
         entry = xa_find(xa, &index, last, XA_PRESENT);     \
         entry;                                             \
         entry = xa_find_after(xa, &index, last, XA_PRESENT))

/**
 * xa_for_each_start() - Iterate over a portion of an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 * @start: First index to retrieve from array.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  You may modify @index during the iteration if you
 * want to skip or reprocess indices.  It is safe to modify the array
 * during the iteration.  At the end of the iteration, @entry will be set
 * to NULL and @index will have a value less than or equal to max.
 *
 * xa_for_each_start() is O(n.log(n)) while xas_for_each() is O(n).  You have
 * to handle your own locking with xas_for_each(), and if you have to unlock
 * after each iteration, it will also end up being O(n.log(n)).
 * xa_for_each_start() will spin if it hits a retry entry; if you intend to
 * see retry entries, you should use the xas_for_each() iterator instead.
 * The xas_for_each() iterator will expand into more inline code than
 * xa_for_each_start().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define xa_for_each_start(xa, index, entry, start) \
    xa_for_each_range(xa, index, entry, start, ULONG_MAX)

/**
 * xa_for_each() - Iterate over present entries in an XArray.
 * @xa: XArray.
 * @index: Index of @entry.
 * @entry: Entry retrieved from array.
 *
 * During the iteration, @entry will have the value of the entry stored
 * in @xa at @index.  You may modify @index during the iteration if you want
 * to skip or reprocess indices.  It is safe to modify the array during the
 * iteration.  At the end of the iteration, @entry will be set to NULL and
 * @index will have a value less than or equal to max.
 *
 * xa_for_each() is O(n.log(n)) while xas_for_each() is O(n).  You have
 * to handle your own locking with xas_for_each(), and if you have to unlock
 * after each iteration, it will also end up being O(n.log(n)).  xa_for_each()
 * will spin if it hits a retry entry; if you intend to see retry entries,
 * you should use the xas_for_each() iterator instead.  The xas_for_each()
 * iterator will expand into more inline code than xa_for_each().
 *
 * Context: Any context.  Takes and releases the RCU lock.
 */
#define xa_for_each(xa, index, entry) \
    xa_for_each_start(xa, index, entry, 0)

/**
 * xas_reset() - Reset an XArray operation state.
 * @xas: XArray operation state.
 *
 * Resets the error or walk state of the @xas so future walks of the
 * array will start from the root.  Use this if you have dropped the
 * xarray lock and want to reuse the xa_state.
 *
 * Context: Any context.
 */
static inline void xas_reset(struct xa_state *xas)
{
    xas->xa_node = XAS_RESTART;
}

/**
 * xa_is_retry() - Is the entry a retry entry?
 * @entry: Entry retrieved from the XArray
 *
 * Return: %true if the entry is a retry entry.
 */
static inline bool xa_is_retry(const void *entry)
{
    return unlikely(entry == XA_RETRY_ENTRY);
}

/**
 * xas_retry() - Retry the operation if appropriate.
 * @xas: XArray operation state.
 * @entry: Entry from xarray.
 *
 * The advanced functions may sometimes return an internal entry, such as
 * a retry entry or a zero entry.  This function sets up the @xas to restart
 * the walk from the head of the array if needed.
 *
 * Context: Any context.
 * Return: true if the operation needs to be retried.
 */
static inline bool xas_retry(struct xa_state *xas, const void *entry)
{
    if (xa_is_zero(entry))
        return true;
    if (!xa_is_retry(entry))
        return false;
    xas_reset(xas);
    return true;
}

/* Private */
static inline struct xa_node *
xa_parent(const struct xarray *xa, const struct xa_node *node)
{
    return rcu_dereference_check(node->parent);
}

void *xa_erase(struct xarray *, unsigned long index);

/**
 * xas_set_update() - Set up XArray operation state for a callback.
 * @xas: XArray operation state.
 * @update: Function to call when updating a node.
 *
 * The XArray can notify a caller after it has updated an xa_node.
 * This is advanced functionality and is only needed by the page cache.
 */
static inline void xas_set_update(struct xa_state *xas, xa_update_node_t update)
{
    xas->xa_update = update;
}

static inline void xas_set_lru(struct xa_state *xas, struct list_lru *lru)
{
    xas->xa_lru = lru;
}

/**
 * xas_set_order() - Set up XArray operation state for a multislot entry.
 * @xas: XArray operation state.
 * @index: Target of the operation.
 * @order: Entry occupies 2^@order indices.
 */
static inline void xas_set_order(struct xa_state *xas, unsigned long index,
                                 unsigned int order)
{
    BUG_ON(order > 0);
    xas_set(xas, index);
}

static inline int xa_get_order(struct xarray *xa, unsigned long index)
{
    return 0;
}

static inline void xas_split(struct xa_state *xas, void *entry,
                             unsigned int order)
{
    xas_store(xas, entry);
}

static inline void xas_split_alloc(struct xa_state *xas, void *entry,
                                   unsigned int order, gfp_t gfp)
{
}

/**
 * xas_for_each_conflict() - Iterate over a range of an XArray.
 * @xas: XArray operation state.
 * @entry: Entry retrieved from the array.
 *
 * The loop body will be executed for each entry in the XArray that
 * lies within the range specified by @xas.  If the loop terminates
 * normally, @entry will be %NULL.  The user may break out of the loop,
 * which will leave @entry set to the conflicting entry.  The caller
 * may also call xa_set_err() to exit the loop while setting an error
 * to record the reason.
 */
#define xas_for_each_conflict(xas, entry) \
    while ((entry = xas_find_conflict(xas)))

void *xa_load(struct xarray *, unsigned long index);

void *xa_store(struct xarray *, unsigned long index, void *entry, gfp_t);

void xa_destroy(struct xarray *);

/**
 * xa_empty() - Determine if an array has any present entries.
 * @xa: XArray.
 *
 * Context: Any context.
 * Return: %true if the array contains only NULL pointers.
 */
static inline bool xa_empty(const struct xarray *xa)
{
    return xa->xa_head == NULL;
}

/**
 * xas_next_entry() - Advance iterator to next present entry.
 * @xas: XArray operation state.
 * @max: Highest index to return.
 *
 * xas_next_entry() is an inline function to optimise xarray traversal for
 * speed.  It is equivalent to calling xas_find(), and will call xas_find()
 * for all the hard cases.
 *
 * Return: The next present entry after the one currently referred to by @xas.
 */
static inline void *xas_next_entry(struct xa_state *xas, unsigned long max)
{
    struct xa_node *node = xas->xa_node;
    void *entry;

    if (unlikely(xas_not_node(node) || node->shift ||
                 xas->xa_offset != (xas->xa_index & XA_CHUNK_MASK)))
        return xas_find(xas, max);

    do {
        if (unlikely(xas->xa_index >= max))
            return xas_find(xas, max);
        if (unlikely(xas->xa_offset == XA_CHUNK_MASK))
            return xas_find(xas, max);
        entry = xa_entry(xas->xa, node, xas->xa_offset + 1);
        if (unlikely(xa_is_internal(entry)))
            return xas_find(xas, max);
        xas->xa_offset++;
        xas->xa_index++;
    } while (!entry);

    return entry;
}

#endif /* _LINUX_XARRAY_H */
