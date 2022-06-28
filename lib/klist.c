// SPDX-License-Identifier: GPL-2.0-only
/*
 * klist.c - Routines for manipulating klists.
 *
 * Copyright (C) 2005 Patrick Mochel
 *
 * This klist interface provides a couple of structures that wrap around
 * struct list_head to provide explicit list "head" (struct klist) and list
 * "node" (struct klist_node) objects. For struct klist, a spinlock is
 * included that protects access to the actual list itself. struct
 * klist_node provides a pointer to the klist that owns it and a kref
 * reference count that indicates the number of current users of that node
 * in the list.
 *
 * The entire point is to provide an interface for iterating over a list
 * that is safe and allows for modification of the list during the
 * iteration (e.g. insertion and removal), including modification of the
 * current node on the list.
 *
 * It works using a 3rd object type - struct klist_iter - that is declared
 * and initialized before an iteration. klist_next() is used to acquire the
 * next element in the list. It returns NULL if there are no more items.
 * Internally, that routine takes the klist's lock, decrements the
 * reference count of the previous klist_node and increments the count of
 * the next klist_node. It then drops the lock and returns.
 *
 * There are primitives for adding and removing nodes to/from a klist.
 * When deleting, klist_del() will simply decrement the reference count.
 * Only when the count goes to 0 is the node removed from the list.
 * klist_remove() will try to delete the node from the list and block until
 * it is actually removed. This is useful for objects (like devices) that
 * have been removed from the system and must be freed (but must wait until
 * all accessors have finished).
 */

#include <linux/klist.h>
#include <linux/export.h>
#include <linux/sched.h>

/*
 * Use the lowest bit of n_klist to mark deleted nodes and exclude
 * dead ones from iteration.
 */
#define KNODE_DEAD          1LU
#define KNODE_KLIST_MASK    ~KNODE_DEAD

static bool knode_dead(struct klist_node *knode)
{
    return (unsigned long)knode->n_klist & KNODE_DEAD;
}

static void knode_set_klist(struct klist_node *knode, struct klist *klist)
{
    knode->n_klist = klist;
    /* no knode deserves to start its life dead */
    WARN_ON(knode_dead(knode));
}

static void klist_node_init(struct klist *k, struct klist_node *n)
{
    INIT_LIST_HEAD(&n->n_node);
    kref_init(&n->n_ref);
    knode_set_klist(n, k);
    if (k->get)
        k->get(n);
}

static void add_tail(struct klist *k, struct klist_node *n)
{
    spin_lock(&k->k_lock);
    list_add_tail(&n->n_node, &k->k_list);
    spin_unlock(&k->k_lock);
}

/**
 * klist_add_tail - Initialize a klist_node and add it to back.
 * @n: node we're adding.
 * @k: klist it's going on.
 */
void klist_add_tail(struct klist_node *n, struct klist *k)
{
    klist_node_init(k, n);
    add_tail(k, n);
}
EXPORT_SYMBOL_GPL(klist_add_tail);

/**
 * klist_init - Initialize a klist structure.
 * @k: The klist we're initializing.
 * @get: The get function for the embedding object (NULL if none)
 * @put: The put function for the embedding object (NULL if none)
 *
 * Initialises the klist structure.  If the klist_node structures are
 * going to be embedded in refcounted objects (necessary for safe
 * deletion) then the get/put arguments are used to initialise
 * functions that take and release references on the embedding
 * objects.
 */
void klist_init(struct klist *k, void (*get)(struct klist_node *),
        void (*put)(struct klist_node *))
{
    INIT_LIST_HEAD(&k->k_list);
    spin_lock_init(&k->k_lock);
    k->get = get;
    k->put = put;
}
EXPORT_SYMBOL_GPL(klist_init);
