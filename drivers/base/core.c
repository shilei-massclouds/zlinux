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

struct class_dir {
    struct kobject kobj;
    struct class *class;
};

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

struct kobject *sysfs_dev_char_kobj;
struct kobject *sysfs_dev_block_kobj;

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

struct kobject *virtual_device_parent(struct device *dev)
{
    static struct kobject *virtual_dir = NULL;

    if (!virtual_dir)
        virtual_dir = kobject_create_and_add("virtual", &devices_kset->kobj);

    return virtual_dir;
}

static DEFINE_MUTEX(gdp_mutex);

#define to_class_dir(obj) container_of(obj, struct class_dir, kobj)

static void class_dir_release(struct kobject *kobj)
{
    struct class_dir *dir = to_class_dir(kobj);
    kfree(dir);
}

static struct kobj_type class_dir_ktype = {
    .release    = class_dir_release,
#if 0
    .sysfs_ops  = &kobj_sysfs_ops,
    .child_ns_type  = class_dir_child_ns_type
#endif
};

static struct kobject *
class_dir_create_and_add(struct class *class, struct kobject *parent_kobj)
{
    struct class_dir *dir;
    int retval;

    dir = kzalloc(sizeof(*dir), GFP_KERNEL);
    if (!dir)
        return ERR_PTR(-ENOMEM);

    dir->class = class;
    kobject_init(&dir->kobj, &class_dir_ktype);

    dir->kobj.kset = &class->p->glue_dirs;

    retval = kobject_add(&dir->kobj, parent_kobj, "%s", class->name);
    if (retval < 0) {
        kobject_put(&dir->kobj);
        return ERR_PTR(retval);
    }
    return &dir->kobj;
}

static struct kobject *
get_device_parent(struct device *dev, struct device *parent)
{
    if (dev->class) {
        struct kobject *kobj = NULL;
        struct kobject *parent_kobj;
        struct kobject *k;

        /*
         * If we have no parent, we live in "virtual".
         * Class-devices with a non class-device as parent, live
         * in a "glue" directory to prevent namespace collisions.
         */
        if (parent == NULL)
            parent_kobj = virtual_device_parent(dev);
        else if (parent->class && !dev->class->ns_type)
            return &parent->kobj;
        else
            parent_kobj = &parent->kobj;

        mutex_lock(&gdp_mutex);

        /* find our class-directory at the parent and reference it */
        spin_lock(&dev->class->p->glue_dirs.list_lock);
        list_for_each_entry(k, &dev->class->p->glue_dirs.list, entry)
            if (k->parent == parent_kobj) {
                kobj = kobject_get(k);
                break;
            }
        spin_unlock(&dev->class->p->glue_dirs.list_lock);
        if (kobj) {
            mutex_unlock(&gdp_mutex);
            return kobj;
        }

        /* or create a new class-directory at the parent device */
        k = class_dir_create_and_add(dev->class, parent_kobj);
        /* do not emit an uevent for this simple "glue" directory */
        mutex_unlock(&gdp_mutex);
        return k;
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

#if 0
    /* notify platform of device entry */
    device_platform_notify(dev);

    error = device_create_file(dev, &dev_attr_uevent);
    if (error)
        goto attrError;

    error = device_add_class_symlinks(dev);
    if (error)
        goto SymlinkError;
    error = device_add_attrs(dev);
    if (error)
        goto AttrsError;
#endif

    error = bus_add_device(dev);
    if (error)
        goto BusError;

#if 0
    error = dpm_sysfs_add(dev);
    if (error)
        goto DPMError;
    device_pm_add(dev);

    if (MAJOR(dev->devt)) {
        error = device_create_file(dev, &dev_attr_dev);
        if (error)
            goto DevAttrError;

        error = device_create_sys_dev_entry(dev);
        if (error)
            goto SysEntryError;

        devtmpfs_create_node(dev);
    }

    /* Notify clients of device addition.  This call must come
     * after dpm_sysfs_add() and before kobject_uevent().
     */
    if (dev->bus)
        blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
                         BUS_NOTIFY_ADD_DEVICE, dev);

    kobject_uevent(&dev->kobj, KOBJ_ADD);
#endif

    /*
     * Check if any of the other devices (consumers) have been waiting for
     * this device (supplier) to be added so that they can create a device
     * link to it.
     *
     * This needs to happen after device_pm_add() because device_link_add()
     * requires the supplier be registered before it's called.
     *
     * But this also needs to happen before bus_probe_device() to make sure
     * waiting consumers can link to it before the driver is bound to the
     * device and the driver sync_state callback is called for this device.
     */
    if (dev->fwnode && !dev->fwnode->dev) {
        dev->fwnode->dev = dev;
#if 0
        fw_devlink_link_device(dev);
#endif
    }

    bus_probe_device(dev);

#if 0
    /*
     * If all driver registration is done and a newly added device doesn't
     * match with any driver, don't block its consumers from probing in
     * case the consumer device is able to operate without this supplier.
     */
    if (dev->fwnode && fw_devlink_drv_reg_done && !dev->can_match)
        fw_devlink_unblock_consumers(dev);
#endif

    if (parent)
        klist_add_tail(&dev->p->knode_parent, &parent->p->klist_children);

    if (dev->class) {
        mutex_lock(&dev->class->p->mutex);
        /* tie the class to the device */
        klist_add_tail(&dev->p->knode_class, &dev->class->p->klist_devices);

#if 0
        /* notify any interfaces that the device is here */
        list_for_each_entry(class_intf, &dev->class->p->interfaces, node)
            if (class_intf->add_dev)
                class_intf->add_dev(dev, class_intf);
#endif
        mutex_unlock(&dev->class->p->mutex);
    }

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
    sysfs_dev_block_kobj = kobject_create_and_add("block", dev_kobj);
    if (!sysfs_dev_block_kobj)
        goto block_kobj_err;
    sysfs_dev_char_kobj = kobject_create_and_add("char", dev_kobj);
    if (!sysfs_dev_char_kobj)
        goto char_kobj_err;

    return 0;

 char_kobj_err:
    //kobject_put(sysfs_dev_block_kobj);
 block_kobj_err:
    kobject_put(dev_kobj);
 dev_kobj_err:
    kset_unregister(devices_kset);
    return -ENOMEM;
}

/**
 * dev_err_probe - probe error check and log helper
 * @dev: the pointer to the struct device
 * @err: error value to test
 * @fmt: printf-style format string
 * @...: arguments as specified in the format string
 *
 * This helper implements common pattern present in probe functions for error
 * checking: print debug or error message depending if the error value is
 * -EPROBE_DEFER and propagate error upwards.
 * In case of -EPROBE_DEFER it sets also defer probe reason, which can be
 * checked later by reading devices_deferred debugfs attribute.
 * It replaces code sequence::
 *
 *  if (err != -EPROBE_DEFER)
 *      dev_err(dev, ...);
 *  else
 *      dev_dbg(dev, ...);
 *  return err;
 *
 * with::
 *
 *  return dev_err_probe(dev, err, ...);
 *
 * Note that it is deemed acceptable to use this function for error
 * prints during probe even if the @err is known to never be -EPROBE_DEFER.
 * The benefit compared to a normal dev_err() is the standardized format
 * of the error code and the fact that the error code is returned.
 *
 * Returns @err.
 *
 */
int dev_err_probe(const struct device *dev,
                  int err, const char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;

    if (err != -EPROBE_DEFER) {
        pr_err("error %pe: %pV", ERR_PTR(err), &vaf);
    } else {
        //device_set_deferred_probe_reason(dev, &vaf);
        pr_debug("error %pe: %pV", ERR_PTR(err), &vaf);
    }

    va_end(args);

    return err;
}
EXPORT_SYMBOL_GPL(dev_err_probe);

static void device_create_release(struct device *dev)
{
    pr_debug("device: '%s': %s\n", dev_name(dev), __func__);
    kfree(dev);
}

static __printf(6, 0) struct device *
device_create_groups_vargs(struct class *class, struct device *parent,
                           dev_t devt, void *drvdata,
                           const struct attribute_group **groups,
                           const char *fmt, va_list args)
{
    struct device *dev = NULL;
    int retval = -ENODEV;

    if (class == NULL || IS_ERR(class))
        goto error;

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev) {
        retval = -ENOMEM;
        goto error;
    }

    device_initialize(dev);
    dev->devt = devt;
    dev->class = class;
    dev->parent = parent;
    //dev->groups = groups;
    dev->release = device_create_release;
    dev_set_drvdata(dev, drvdata);

    retval = kobject_set_name_vargs(&dev->kobj, fmt, args);
    if (retval)
        goto error;

    retval = device_add(dev);
    if (retval)
        goto error;

    return dev;

error:
    put_device(dev);
    return ERR_PTR(retval);
}

/**
 * device_create - creates a device and registers it with sysfs
 * @class: pointer to the struct class that this device should be registered to
 * @parent: pointer to the parent struct device of this new device, if any
 * @devt: the dev_t for the char device to be added
 * @drvdata: the data to be added to the device for callbacks
 * @fmt: string for the device's name
 *
 * This function can be used by char device classes.  A struct device
 * will be created in sysfs, registered to the specified class.
 *
 * A "dev" file will be created, showing the dev_t for the device, if
 * the dev_t is not 0,0.
 * If a pointer to a parent struct device is passed in, the newly created
 * struct device will be a child of that device in sysfs.
 * The pointer to the struct device will be returned from the call.
 * Any further sysfs files that might be required can be created using this
 * pointer.
 *
 * Returns &struct device pointer on success, or ERR_PTR() on error.
 *
 * Note: the struct class passed to this function must have previously
 * been created with a call to class_create().
 */
struct device *device_create(struct class *class, struct device *parent,
                             dev_t devt, void *drvdata, const char *fmt, ...)
{
    va_list vargs;
    struct device *dev;

    va_start(vargs, fmt);
    dev = device_create_groups_vargs(class, parent, devt, drvdata, NULL,
                                     fmt, vargs);
    va_end(vargs);
    return dev;
}
EXPORT_SYMBOL_GPL(device_create);
