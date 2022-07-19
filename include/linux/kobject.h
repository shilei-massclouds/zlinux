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
#include <linux/uidgid.h>

#define UEVENT_NUM_ENVP         64      /* number of env pointers */
#define UEVENT_BUFFER_SIZE      2048    /* buffer for the variables */

struct kobject {
    const char          *name;
    struct list_head    entry;
    struct kobject      *parent;
    struct kset         *kset;
    const struct kobj_type    *ktype;
    struct kref         kref;

    unsigned int state_initialized:1;
    unsigned int state_in_sysfs:1;
    unsigned int state_add_uevent_sent:1;
    unsigned int state_remove_uevent_sent:1;
    unsigned int uevent_suppress:1;
};

struct kset_uevent_ops {
#if 0
    int (* const filter)(struct kobject *kobj);
    const char *(* const name)(struct kobject *kobj);
    int (* const uevent)(struct kobject *kobj, struct kobj_uevent_env *env);
#endif
};

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
struct kset {
    struct list_head list;
    spinlock_t list_lock;
    struct kobject kobj;
    const struct kset_uevent_ops *uevent_ops;
} __randomize_layout;

struct kobj_type {
    void (*release)(struct kobject *kobj);
#if 0
    const struct sysfs_ops *sysfs_ops;
    const struct attribute_group **default_groups;
    const struct kobj_ns_type_operations *
        (*child_ns_type)(struct kobject *kobj);
    const void *(*namespace)(struct kobject *kobj);
    void (*get_ownership)(struct kobject *kobj, kuid_t *uid, kgid_t *gid);
#endif
};

struct kobj_uevent_env {
    char *argv[3];
    char *envp[UEVENT_NUM_ENVP];
    int envp_idx;
    char buf[UEVENT_BUFFER_SIZE];
    int buflen;
};

extern void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);

extern __printf(4, 5) __must_check
int kobject_init_and_add(struct kobject *kobj,
                         const struct kobj_type *ktype, struct kobject *parent,
                         const char *fmt, ...);

extern __printf(2, 3)
int kobject_set_name(struct kobject *kobj, const char *name, ...);

extern __printf(2, 0)
int kobject_set_name_vargs(struct kobject *kobj,
                           const char *fmt, va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
    return kobj->name;
}

extern struct kobject *kobject_get(struct kobject *kobj);
extern void kobject_put(struct kobject *kobj);

static inline const struct kobj_type *get_ktype(struct kobject *kobj)
{
    return kobj->ktype;
}

int kobject_add(struct kobject *kobj, struct kobject *parent,
                const char *fmt, ...);

static inline struct kset *to_kset(struct kobject *kobj)
{
    return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

static inline struct kset *kset_get(struct kset *k)
{
    return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
    kobject_put(&k->kobj);
}

extern struct kobject * __must_check
kobject_create_and_add(const char *name, struct kobject *parent);

extern struct kset * __must_check
kset_create_and_add(const char *name,
                    const struct kset_uevent_ops *u,
                    struct kobject *parent_kobj);

extern void kset_init(struct kset *kset);
extern int __must_check kset_register(struct kset *kset);
extern void kset_unregister(struct kset *kset);

extern struct kobject *kset_find_obj(struct kset *, const char *);

#endif /* _KOBJECT_H_ */
