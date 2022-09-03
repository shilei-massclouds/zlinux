/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_NULLS_H
#define _LINUX_LIST_NULLS_H

#include <linux/poison.h>
#include <linux/const.h>

/*
 * Special version of lists, where end of list is not a NULL pointer,
 * but a 'nulls' marker, which can have many different values.
 * (up to 2^31 different values guaranteed on all platforms)
 *
 * In the standard hlist, termination of a list is the NULL pointer.
 * In this special 'nulls' variant, we use the fact that objects stored in
 * a list are aligned on a word (4 or 8 bytes alignment).
 * We therefore use the last significant bit of 'ptr' :
 * Set to 1 : This is a 'nulls' end-of-list marker (ptr >> 1)
 * Set to 0 : This is a pointer to some object (ptr)
 */

struct hlist_nulls_head {
    struct hlist_nulls_node *first;
};

struct hlist_nulls_node {
    struct hlist_nulls_node *next, **pprev;
};

#endif /* _LINUX_LIST_NULLS_H */
