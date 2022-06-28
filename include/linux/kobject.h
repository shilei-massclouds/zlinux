// SPDX-License-Identifier: GPL-2.0
/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * Please read Documentation/core-api/kobject.rst before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
//#include <linux/kobject_ns.h>
#include <linux/kernel.h>
//#include <linux/wait.h>
#include <linux/atomic.h>
//#include <linux/workqueue.h>
//#include <linux/uidgid.h>

struct kobject {
    const char          *name;
    struct list_head    entry;
    struct kobj_type    *ktype;
    struct kref         kref;

    unsigned int state_initialized:1;
};

struct kobj_type {
    void (*release)(struct kobject *kobj);
};

extern void kobject_init(struct kobject *kobj, struct kobj_type *ktype);

extern __printf(2, 3)
int kobject_set_name(struct kobject *kobj, const char *name, ...);

extern __printf(2, 0)
int kobject_set_name_vargs(struct kobject *kobj,
                           const char *fmt, va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
    return kobj->name;
}

#endif /* _KOBJECT_H_ */
