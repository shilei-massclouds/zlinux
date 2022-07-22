// SPDX-License-Identifier: GPL-2.0
/*
 * class.c - basic device class management
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2003-2004 Greg Kroah-Hartman
 * Copyright (c) 2003-2004 IBM Corp.
 */

#include <linux/device/class.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include "base.h"

/* Hotplug events for classes go to the class subsys */
static struct kset *class_kset;

static void class_release(struct kobject *kobj)
{
    struct subsys_private *cp = to_subsys_private(kobj);
    struct class *class = cp->class;

    pr_debug("class '%s': release.\n", class->name);

    if (class->class_release)
        class->class_release(class);
    else
        pr_debug("class '%s' does not have a release() function, "
                 "be careful\n", class->name);

    kfree(cp);
}

static struct kobj_type class_ktype = {
    //.sysfs_ops  = &class_sysfs_ops,
    .release    = class_release,
    //.child_ns_type  = class_child_ns_type,
};

static struct device *klist_class_to_dev(struct klist_node *n)
{
    struct device_private *p = to_device_private_class(n);
    return p->device;
}

static void klist_class_dev_get(struct klist_node *n)
{
    struct device *dev = klist_class_to_dev(n);

    get_device(dev);
}

static void klist_class_dev_put(struct klist_node *n)
{
    struct device *dev = klist_class_to_dev(n);

    put_device(dev);
}

static void class_put(struct class *cls)
{
    if (cls)
        kset_put(&cls->p->subsys);
}

/**
 * class_dev_iter_init - initialize class device iterator
 * @iter: class iterator to initialize
 * @class: the class we wanna iterate over
 * @start: the device to start iterating from, if any
 * @type: device_type of the devices to iterate over, NULL for all
 *
 * Initialize class iterator @iter such that it iterates over devices
 * of @class.  If @start is set, the list iteration will start there,
 * otherwise if it is NULL, the iteration starts at the beginning of
 * the list.
 */
void class_dev_iter_init(struct class_dev_iter *iter, struct class *class,
             struct device *start, const struct device_type *type)
{
    struct klist_node *start_knode = NULL;

    if (start)
        start_knode = &start->p->knode_class;
    klist_iter_init_node(&class->p->klist_devices, &iter->ki, start_knode);
    iter->type = type;
}
EXPORT_SYMBOL_GPL(class_dev_iter_init);

/**
 * class_dev_iter_next - iterate to the next device
 * @iter: class iterator to proceed
 *
 * Proceed @iter to the next device and return it.  Returns NULL if
 * iteration is complete.
 *
 * The returned device is referenced and won't be released till
 * iterator is proceed to the next device or exited.  The caller is
 * free to do whatever it wants to do with the device including
 * calling back into class code.
 */
struct device *class_dev_iter_next(struct class_dev_iter *iter)
{
    struct klist_node *knode;
    struct device *dev;

    while (1) {
        knode = klist_next(&iter->ki);
        if (!knode)
            return NULL;
        dev = klist_class_to_dev(knode);
        if (!iter->type || iter->type == dev->type)
            return dev;
    }
}
EXPORT_SYMBOL_GPL(class_dev_iter_next);

/**
 * class_dev_iter_exit - finish iteration
 * @iter: class iterator to finish
 *
 * Finish an iteration.  Always call this function after iteration is
 * complete whether the iteration ran till the end or not.
 */
void class_dev_iter_exit(struct class_dev_iter *iter)
{
    klist_iter_exit(&iter->ki);
}
EXPORT_SYMBOL_GPL(class_dev_iter_exit);

int __class_register(struct class *cls, struct lock_class_key *key)
{
    struct subsys_private *cp;
    int error;

    pr_info("device class '%s': registering\n", cls->name);

    cp = kzalloc(sizeof(*cp), GFP_KERNEL);
    if (!cp)
        return -ENOMEM;
    klist_init(&cp->klist_devices, klist_class_dev_get, klist_class_dev_put);
    INIT_LIST_HEAD(&cp->interfaces);
    kset_init(&cp->glue_dirs);
    __mutex_init(&cp->mutex, "subsys mutex", key);
    error = kobject_set_name(&cp->subsys.kobj, "%s", cls->name);
    if (error) {
        kfree(cp);
        return error;
    }

    /* set the default /sys/dev directory for devices of this class */
    if (!cls->dev_kobj)
        cls->dev_kobj = sysfs_dev_char_kobj;

    /* let the block class directory show up in the root of sysfs */
    cp->subsys.kobj.kset = class_kset;
    cp->subsys.kobj.ktype = &class_ktype;
    cp->class = cls;
    cls->p = cp;

    error = kset_register(&cp->subsys);
    if (error) {
        kfree(cp);
        return error;
    }

#if 0
    error = class_add_groups(class_get(cls), cls->class_groups);
    class_put(cls);
#endif
    return error;
}

int __init classes_init(void)
{
    class_kset = kset_create_and_add("class", NULL, NULL);
    if (!class_kset)
        return -ENOMEM;
    return 0;
}
