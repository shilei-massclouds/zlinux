// SPDX-License-Identifier: GPL-2.0
/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/ioport.h>
#include <linux/compiler.h>
#if 0
#include <linux/dev_printk.h>
#include <linux/energy_model.h>
#include <linux/klist.h>
#endif
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/gfp.h>
#include <linux/device/bus.h>
#if 0
#include <linux/pm.h>
#include <linux/uidgid.h>
#include <linux/overflow.h>
#include <linux/device/class.h>
#include <linux/device/driver.h>
#include <asm/device.h>
#endif

/**
 * enum dl_dev_state - Device driver presence tracking information.
 * @DL_DEV_NO_DRIVER: There is no driver attached to the device.
 * @DL_DEV_PROBING: A driver is probing.
 * @DL_DEV_DRIVER_BOUND: The driver has been bound to the device.
 * @DL_DEV_UNBINDING: The driver is unbinding from the device.
 */
enum dl_dev_state {
    DL_DEV_NO_DRIVER = 0,
    DL_DEV_PROBING,
    DL_DEV_DRIVER_BOUND,
    DL_DEV_UNBINDING,
};

/*
 * The type of device, "struct device" is embedded in. A class
 * or bus can contain devices of different types
 * like "partitions" and "disks", "mouse" and "event".
 * This identifies the device type and carries type-specific
 * information, equivalent to the kobj_type of a kobject.
 * If "name" is specified, the uevent will contain it in
 * the DEVTYPE variable.
 */
struct device_type {
    const char *name;
#if 0
    const struct attribute_group **groups;
    int (*uevent)(struct device *dev, struct kobj_uevent_env *env);
    char *(*devnode)(struct device *dev, umode_t *mode,
                     kuid_t *uid, kgid_t *gid);
    void (*release)(struct device *dev);

    const struct dev_pm_ops *pm;
#endif
};

struct device {

    struct kobject  kobj;
    struct device   *parent;

    struct device_private *p;

    const char *init_name;              /* initial name of the device */
    const struct device_type *type;

    struct bus_type *bus;               /* type of bus device is on */

#if 0
    struct device_driver *driver;       /* which driver has allocated this
                                           device */
#endif

    void *platform_data;                /* Platform specific data,
                                           device core doesn't touch it */

    void *driver_data;                  /* Driver data, set and get with
                                           dev_set_drvdata/dev_get_drvdata */

    struct mutex mutex;                 /* mutex to synchronize calls to
                                           its driver. */

#if 0
    struct dev_links_info   links;
#endif

    struct list_head        dma_pools;  /* dma pools (if dma'ble) */

    struct device_node      *of_node;   /* associated device tree node */
    struct fwnode_handle    *fwnode;    /* firmware device node */

    u32 id;     /* device instance */

    spinlock_t          devres_lock;
    struct list_head    devres_head;

    struct class *class;

    void (*release)(struct device *dev);
};

/*
 * High level routines for use by the bus drivers
 */
int __must_check device_register(struct device *dev);
void device_unregister(struct device *dev);
void device_initialize(struct device *dev);

__printf(2, 3) int dev_set_name(struct device *dev, const char *name, ...);

static inline const char *dev_name(const struct device *dev)
{
    /* Use the init name until the kobject becomes available */
    if (dev->init_name)
        return dev->init_name;

    return kobject_name(&dev->kobj);
}

int __must_check device_add(struct device *dev);

/*
 * get_device - atomically increment the reference count for the device.
 *
 */
struct device *get_device(struct device *dev);
void put_device(struct device *dev);

static inline struct device *kobj_to_dev(struct kobject *kobj)
{
    return container_of(kobj, struct device, kobj);
}

#endif /* _DEVICE_H_ */
