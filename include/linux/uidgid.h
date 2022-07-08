/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UIDGID_H
#define _LINUX_UIDGID_H

/*
 * A set of types for the internal kernel types representing uids and gids.
 *
 * The types defined in this header allow distinguishing which uids and gids in
 * the kernel are values used by userspace and which uid and gid values are
 * the internal kernel values.  With the addition of user namespaces the values
 * can be different.  Using the type system makes it possible for the compiler
 * to detect when we overlook these differences.
 *
 */
#include <linux/types.h>
#if 0
#include <linux/highuid.h>
#endif

typedef struct {
    uid_t val;
} kuid_t;


typedef struct {
    gid_t val;
} kgid_t;

#endif /* _LINUX_UIDGID_H */
