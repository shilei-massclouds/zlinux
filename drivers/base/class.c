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
