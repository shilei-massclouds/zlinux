// SPDX-License-Identifier: GPL-2.0
/*
 * The class-specific portions of the driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 * Copyright (c) 2012-2019 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2012-2019 Linux Foundation
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_CLASS_H_
#define _DEVICE_CLASS_H_

#include <linux/kobject.h>
#include <linux/klist.h>
#include <linux/pm.h>
#include <linux/device/bus.h>

struct device;
struct fwnode_handle;

/**
 * struct class - device classes
 * @name:   Name of the class.
 * @owner:  The module owner.
 * @class_groups: Default attributes of this class.
 * @dev_groups: Default attributes of the devices that belong to the class.
 * @dev_kobj:   The kobject that represents this class and links it into the hierarchy.
 * @dev_uevent: Called when a device is added, removed from this class, or a
 *      few other things that generate uevents to add the environment
 *      variables.
 * @devnode:    Callback to provide the devtmpfs.
 * @class_release: Called to release this class.
 * @dev_release: Called to release the device.
 * @shutdown_pre: Called at shut-down time before driver shutdown.
 * @ns_type:    Callbacks so sysfs can detemine namespaces.
 * @namespace:  Namespace of the device belongs to this class.
 * @get_ownership: Allows class to specify uid/gid of the sysfs directories
 *      for the devices belonging to the class. Usually tied to
 *      device's namespace.
 * @pm:     The default device power management operations of this class.
 * @p:      The private data of the driver core, no one other than the
 *      driver core can touch this.
 *
 * A class is a higher-level view of a device that abstracts out low-level
 * implementation details. Drivers may see a SCSI disk or an ATA disk, but,
 * at the class level, they are all simply disks. Classes allow user space
 * to work with devices based on what they do, rather than how they are
 * connected or how they work.
 */
struct class {
    const char      *name;
    struct module   *owner;

    const struct attribute_group    **class_groups;
    const struct attribute_group    **dev_groups;
    struct kobject          *dev_kobj;

    int (*dev_uevent)(struct device *dev, struct kobj_uevent_env *env);
    char *(*devnode)(struct device *dev, umode_t *mode);

    void (*class_release)(struct class *class);
    void (*dev_release)(struct device *dev);

    int (*shutdown_pre)(struct device *dev);

    const struct kobj_ns_type_operations *ns_type;
    const void *(*namespace)(struct device *dev);

    void (*get_ownership)(struct device *dev, kuid_t *uid, kgid_t *gid);

    const struct dev_pm_ops *pm;

    struct subsys_private *p;
};

#endif  /* _DEVICE_CLASS_H_ */
