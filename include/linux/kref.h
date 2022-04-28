/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kref.h - library routines for handling generic reference counted objects
 *
 * Copyright (C) 2004 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (C) 2004 IBM Corp.
 *
 * based on kobject.h which was:
 * Copyright (C) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (C) 2002-2003 Open Source Development Labs
 */

#ifndef _KREF_H_
#define _KREF_H_

#include <linux/spinlock.h>
#include <linux/refcount.h>

struct kref {
    refcount_t refcount;
};

#define KREF_INIT(n)    { .refcount = REFCOUNT_INIT(n), }

/**
 * kref_init - initialize object.
 * @kref: object in question.
 */
static inline void kref_init(struct kref *kref)
{
    refcount_set(&kref->refcount, 1);
}

#endif /* _KREF_H_ */
