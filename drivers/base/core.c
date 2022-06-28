// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/base/core.c - core driver model code (device registration, etc)
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2006 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2006 Novell, Inc.
 */
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fwnode.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/of_device.h>
#if 0
#include <linux/acpi.h>
#include <linux/cpufreq.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/notifier.h>
#include <linux/blkdev.h>
#include <linux/pm_runtime.h>
#include <linux/netdevice.h>
#include <linux/swiotlb.h>
#include <linux/dma-map-ops.h> /* for dma_default_coherent */
#endif

#include "base.h"

/* /sys/devices/ */
struct kset *devices_kset;

static struct kobject *dev_kobj;

static struct kobj_type device_ktype = {
#if 0
    .release    = device_release,
    .sysfs_ops  = &dev_sysfs_ops,
    .namespace  = device_namespace,
    .get_ownership  = device_get_ownership,
#endif
};

/**
 * dev_set_name - set a device name
 * @dev: device
 * @fmt: format string for the device's name
 */
int dev_set_name(struct device *dev, const char *fmt, ...)
{
    va_list vargs;
    int err;

    va_start(vargs, fmt);
    err = kobject_set_name_vargs(&dev->kobj, fmt, vargs);
    va_end(vargs);
    return err;
}
EXPORT_SYMBOL_GPL(dev_set_name);

static struct kobject *
get_device_parent(struct device *dev, struct device *parent)
{
    if (dev->class) {
        panic("%s: NO implementation!\n", __func__);
    }

    /* subsystems can specify a default root directory for their devices */
    if (!parent && dev->bus && dev->bus->dev_root)
        return &dev->bus->dev_root->kobj;

    if (parent)
        return &parent->kobj;
    return NULL;
}

/**
 * device_initialize - init device structure.
 * @dev: device.
 *
 * This prepares the device for use by other layers by initializing
 * its fields.
 * It is the first half of device_register(), if called by
 * that function, though it can also be called separately, so one
 * may use @dev's fields. In particular, get_device()/put_device()
 * may be used for reference counting of @dev after calling this
 * function.
 *
 * All fields in @dev must be initialized by the caller to 0, except
 * for those explicitly set to some other value.  The simplest
 * approach is to use kzalloc() to allocate the structure containing
 * @dev.
 *
 * NOTE: Use put_device() to give up your reference instead of freeing
 * @dev directly once you have called this function.
 */
void device_initialize(struct device *dev)
{
    dev->kobj.kset = devices_kset;
    kobject_init(&dev->kobj, &device_ktype);
    INIT_LIST_HEAD(&dev->dma_pools);
    mutex_init(&dev->mutex);
    spin_lock_init(&dev->devres_lock);
    INIT_LIST_HEAD(&dev->devres_head);
#if 0
    device_pm_init(dev);
    INIT_LIST_HEAD(&dev->links.consumers);
    INIT_LIST_HEAD(&dev->links.suppliers);
    INIT_LIST_HEAD(&dev->links.defer_sync);
    dev->links.status = DL_DEV_NO_DRIVER;
    dev->dma_io_tlb_mem = &io_tlb_default_mem;
#endif
}
EXPORT_SYMBOL_GPL(device_initialize);

/**
 * get_device - increment reference count for device.
 * @dev: device.
 *
 * This simply forwards the call to kobject_get(), though
 * we do take care to provide for the case that we get a NULL
 * pointer passed in.
 */
struct device *get_device(struct device *dev)
{
    return dev ? kobj_to_dev(kobject_get(&dev->kobj)) : NULL;
}
EXPORT_SYMBOL_GPL(get_device);

/**
 * put_device - decrement reference count.
 * @dev: device in question.
 */
void put_device(struct device *dev)
{
    /* might_sleep(); */
    if (dev)
        kobject_put(&dev->kobj);
}
EXPORT_SYMBOL_GPL(put_device);

/**
 * device_del - delete device from system.
 * @dev: device.
 *
 * This is the first part of the device unregistration
 * sequence. This removes the device from the lists we control
 * from here, has it removed from the other driver model
 * subsystems it was added to in device_add(), and removes it
 * from the kobject hierarchy.
 *
 * NOTE: this should be called manually _iff_ device_add() was
 * also called manually.
 */
void device_del(struct device *dev)
{
    panic("%s: NO implementation!\n", __func__);
}

/**
 * device_unregister - unregister device from system.
 * @dev: device going away.
 *
 * We do this in two parts, like we do device_register(). First,
 * we remove it from all the subsystems with device_del(), then
 * we decrement the reference count via put_device(). If that
 * is the final reference count, the device will be cleaned up
 * via device_release() above. Otherwise, the structure will
 * stick around until the final reference to the device is dropped.
 */
void device_unregister(struct device *dev)
{
    pr_debug("device: '%s': %s\n", dev_name(dev), __func__);
    device_del(dev);
    put_device(dev);
}
EXPORT_SYMBOL_GPL(device_unregister);

static void klist_children_get(struct klist_node *n)
{
    struct device_private *p = to_device_private_parent(n);
    struct device *dev = p->device;

    get_device(dev);
}

static void klist_children_put(struct klist_node *n)
{
    struct device_private *p = to_device_private_parent(n);
    struct device *dev = p->device;

    put_device(dev);
}

static int device_private_init(struct device *dev)
{
    dev->p = kzalloc(sizeof(*dev->p), GFP_KERNEL);
    if (!dev->p)
        return -ENOMEM;
    dev->p->device = dev;
    klist_init(&dev->p->klist_children, klist_children_get, klist_children_put);
    INIT_LIST_HEAD(&dev->p->deferred_probe);
    return 0;
}

static inline struct kobject *get_glue_dir(struct device *dev)
{
    return dev->kobj.parent;
}

/*
 * make sure cleaning up dir as the last step, we need to make
 * sure .release handler of kobject is run with holding the
 * global lock
 */
static void cleanup_glue_dir(struct device *dev, struct kobject *glue_dir)
{
    panic("%s: NO implementation!\n", __func__);
}

static void device_remove_attrs(struct device *dev)
{
    panic("%s: NO implementation!\n", __func__);
}

/**
 * device_add - add device to device hierarchy.
 * @dev: device.
 *
 * This is part 2 of device_register(), though may be called
 * separately _iff_ device_initialize() has been called separately.
 *
 * This adds @dev to the kobject hierarchy via kobject_add(), adds it
 * to the global and sibling lists for the device, then
 * adds it to the other relevant subsystems of the driver model.
 *
 * Do not call this routine or device_register() more than once for
 * any device structure.  The driver model core is not designed to work
 * with devices that get unregistered and then spring back to life.
 * (Among other things, it's very hard to guarantee that all references
 * to the previous incarnation of @dev have been dropped.)  Allocate
 * and register a fresh new struct device instead.
 *
 * NOTE: _Never_ directly free @dev after calling this function, even
 * if it returned an error! Always use put_device() to give up your
 * reference instead.
 *
 * Rule of thumb is: if device_add() succeeds, you should call
 * device_del() when you want to get rid of it. If device_add() has
 * *not* succeeded, use *only* put_device() to drop the reference
 * count.
 */
int device_add(struct device *dev)
{
    struct device *parent;
    struct kobject *kobj;
    struct class_interface *class_intf;
    int error = -EINVAL;
    struct kobject *glue_dir = NULL;

    dev = get_device(dev);
    if (!dev)
        goto done;

    if (!dev->p) {
        error = device_private_init(dev);
        if (error)
            goto done;
    }

    /*
     * for statically allocated devices, which should all be converted
     * some day, we need to initialize the name. We prevent reading back
     * the name, and force the use of dev_name()
     */
    if (dev->init_name) {
        dev_set_name(dev, "%s", dev->init_name);
        dev->init_name = NULL;
    }

    /* subsystems can specify simple device enumeration */
    if (!dev_name(dev) && dev->bus && dev->bus->dev_name)
        dev_set_name(dev, "%s%u", dev->bus->dev_name, dev->id);

    if (!dev_name(dev)) {
        error = -EINVAL;
        goto name_error;
    }

    pr_info("device: '%s': %s\n", dev_name(dev), __func__);

    parent = get_device(dev->parent);
    kobj = get_device_parent(dev, parent);
    if (IS_ERR(kobj)) {
        error = PTR_ERR(kobj);
        goto parent_error;
    }
    if (kobj)
        dev->kobj.parent = kobj;

    /* first, register with generic layer. */
    /* we require the name to be set before, and pass NULL */
    error = kobject_add(&dev->kobj, dev->kobj.parent, NULL);
    if (error) {
        glue_dir = get_glue_dir(dev);
        goto Error;
    }

    error = bus_add_device(dev);
    if (error)
        goto BusError;

    pr_warn("%s: %s END!\n", __func__, dev_name(dev));

 done:
    put_device(dev);
    return error;
 BusError:
    device_remove_attrs(dev);
 Error:
    cleanup_glue_dir(dev, glue_dir);
 parent_error:
    put_device(parent);
 name_error:
    kfree(dev->p);
    dev->p = NULL;
    goto done;
}
EXPORT_SYMBOL_GPL(device_add);

/**
 * device_register - register a device with the system.
 * @dev: pointer to the device structure
 *
 * This happens in two clean steps - initialize the device
 * and add it to the system. The two steps can be called
 * separately, but this is the easiest and most common.
 * I.e. you should only call the two helpers separately if
 * have a clearly defined need to use and refcount the device
 * before it is added to the hierarchy.
 *
 * For more information, see the kerneldoc for device_initialize()
 * and device_add().
 *
 * NOTE: _Never_ directly free @dev after calling this function, even
 * if it returned an error! Always use put_device() to give up the
 * reference initialized in this function instead.
 */
int device_register(struct device *dev)
{
    device_initialize(dev);
    return device_add(dev);
}
EXPORT_SYMBOL_GPL(device_register);

static const struct kset_uevent_ops device_uevent_ops = {
#if 0
    .filter =   dev_uevent_filter,
    .name =     dev_uevent_name,
    .uevent =   dev_uevent,
#endif
};

int __init devices_init(void)
{
    devices_kset = kset_create_and_add("devices", &device_uevent_ops, NULL);
    if (!devices_kset)
        return -ENOMEM;
    dev_kobj = kobject_create_and_add("dev", NULL);
    if (!dev_kobj)
        goto dev_kobj_err;
#if 0
    sysfs_dev_block_kobj = kobject_create_and_add("block", dev_kobj);
    if (!sysfs_dev_block_kobj)
        goto block_kobj_err;
    sysfs_dev_char_kobj = kobject_create_and_add("char", dev_kobj);
    if (!sysfs_dev_char_kobj)
        goto char_kobj_err;
#endif

    return 0;

 char_kobj_err:
    //kobject_put(sysfs_dev_block_kobj);
 block_kobj_err:
    kobject_put(dev_kobj);
 dev_kobj_err:
    kset_unregister(devices_kset);
    return -ENOMEM;
}
