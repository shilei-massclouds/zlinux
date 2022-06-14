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

extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);

#endif  /* _LINUX_RBTREE_H */
