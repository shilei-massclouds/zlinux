/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>


  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  See Documentation/core-api/rbtree.rst for documentation and samples.
*/

#ifndef _LINUX_RBTREE_H
#define _LINUX_RBTREE_H

#include <linux/rbtree_types.h>

#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/rcupdate.h>

#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  (READ_ONCE((root)->rb_node) == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node) \
    ((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node) \
    ((node)->__rb_parent_color = (unsigned long)(node))

extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);

/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
                                struct rb_node **rb_link)
{
    node->__rb_parent_color = (unsigned long)parent;
    node->rb_left = node->rb_right = NULL;

    *rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
    ({ typeof(ptr) ____ptr = (ptr); \
       ____ptr ? rb_entry(____ptr, type, member) : NULL; \
    })

static inline void rb_insert_color_cached(struct rb_node *node,
                                          struct rb_root_cached *root,
                                          bool leftmost)
{
    if (leftmost)
        root->rb_leftmost = node;
    rb_insert_color(node, &root->rb_root);
}

/**
 * rb_add_cached() - insert @node into the leftmost cached tree @tree
 * @node: node to insert
 * @tree: leftmost cached tree to insert @node into
 * @less: operator defining the (partial) node order
 *
 * Returns @node when it is the new leftmost, or NULL.
 */
static __always_inline struct rb_node *
rb_add_cached(struct rb_node *node, struct rb_root_cached *tree,
              bool (*less)(struct rb_node *, const struct rb_node *))
{
    struct rb_node **link = &tree->rb_root.rb_node;
    struct rb_node *parent = NULL;
    bool leftmost = true;

    while (*link) {
        parent = *link;
        if (less(node, parent)) {
            link = &parent->rb_left;
        } else {
            link = &parent->rb_right;
            leftmost = false;
        }
    }

    rb_link_node(node, parent, link);
    rb_insert_color_cached(node, tree, leftmost);

    return leftmost ? node : NULL;
}

static inline struct rb_node *
rb_erase_cached(struct rb_node *node, struct rb_root_cached *root)
{
    struct rb_node *leftmost = NULL;

    if (root->rb_leftmost == node)
        leftmost = root->rb_leftmost = rb_next(node);

    rb_erase(node, &root->rb_root);

    return leftmost;
}

/* Same as rb_first(), but O(1) */
#define rb_first_cached(root) (root)->rb_leftmost

#endif  /* _LINUX_RBTREE_H */
