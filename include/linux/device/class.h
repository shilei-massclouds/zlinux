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

struct class_dev_iter {
    struct klist_iter           ki;
    const struct device_type    *type;
};

extern int __must_check __class_register(struct class *class,
                                         struct lock_class_key *key);
extern void class_unregister(struct class *class);

/* This is a #define to keep the compiler from merging different
 * instances of the __key variable */
#define class_register(class)           \
({                      \
    static struct lock_class_key __key; \
    __class_register(class, &__key);    \
})

extern struct kobject *sysfs_dev_block_kobj;
extern struct kobject *sysfs_dev_char_kobj;

extern void class_dev_iter_init(struct class_dev_iter *iter,
                                struct class *class,
                                struct device *start,
                                const struct device_type *type);
extern struct device *class_dev_iter_next(struct class_dev_iter *iter);
extern void class_dev_iter_exit(struct class_dev_iter *iter);

extern struct class * __must_check
__class_create(struct module *owner, const char *name,
               struct lock_class_key *key);

extern void class_destroy(struct class *cls);

/**
 * class_create - create a struct class structure
 * @owner: pointer to the module that is to "own" this struct class
 * @name: pointer to a string for the name of this class.
 *
 * This is used to create a struct class pointer that can then be used
 * in calls to device_create().
 *
 * Returns &struct class pointer on success, or ERR_PTR() on error.
 *
 * Note, the pointer created here is to be destroyed when finished by
 * making a call to class_destroy().
 */
#define class_create(owner, name)       \
({                      \
    static struct lock_class_key __key; \
    __class_create(owner, name, &__key);    \
})

#endif  /* _DEVICE_CLASS_H_ */
