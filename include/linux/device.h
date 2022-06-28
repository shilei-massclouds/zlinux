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
#if 0
#include <linux/pm.h>
#include <linux/uidgid.h>
#include <linux/overflow.h>
#include <linux/device/bus.h>
#include <linux/device/class.h>
#include <linux/device/driver.h>
#include <asm/device.h>
#endif

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

    struct device_node      *of_node;   /* associated device tree node */
    struct fwnode_handle    *fwnode;    /* firmware device node */

    void (*release)(struct device *dev);
};

void device_initialize(struct device *dev);

__printf(2, 3) int dev_set_name(struct device *dev, const char *name, ...);

#endif /* _DEVICE_H_ */
