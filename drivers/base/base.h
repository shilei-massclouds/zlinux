/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2012 Novell Inc.
 * Copyright (c) 2012-2019 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2012-2019 Linux Foundation
 *
 * Core driver model functions and structures that should not be
 * shared outside of the drivers/base/ directory.
 *
 */
#if 0
#include <linux/notifier.h>
#endif

/**
 * struct subsys_private - structure to hold the private to the driver core portions of the bus_type/class structure.
 *
 * @subsys - the struct kset that defines this subsystem
 * @devices_kset - the subsystem's 'devices' directory
 * @interfaces - list of subsystem interfaces associated
 * @mutex - protect the devices, and interfaces lists.
 *
 * @drivers_kset - the list of drivers associated
 * @klist_devices - the klist to iterate over the @devices_kset
 * @klist_drivers - the klist to iterate over the @drivers_kset
 * @bus_notifier - the bus notifier list for anything that cares about things
 *                 on this bus.
 * @bus - pointer back to the struct bus_type that this structure is associated
 *        with.
 *
 * @glue_dirs - "glue" directory to put in-between the parent device to
 *              avoid namespace conflicts
 * @class - pointer back to the struct class that this structure is associated
 *          with.
 *
 * This structure is the one that is the actual kobject allowing struct
 * bus_type/class to be statically allocated safely.  Nothing outside of the
 * driver core should ever touch these fields.
 */
struct subsys_private {
    struct kset subsys;
    struct kset *devices_kset;
    struct list_head interfaces;
    struct mutex mutex;

    struct kset *drivers_kset;
    struct klist klist_devices;
    struct klist klist_drivers;
    //struct blocking_notifier_head bus_notifier;
    unsigned int drivers_autoprobe:1;
    struct bus_type *bus;

    struct kset glue_dirs;
    struct class *class;
};
#define to_subsys_private(obj) \
    container_of(obj, struct subsys_private, subsys.kobj)

/**
 * struct device_private - structure to hold the private to the driver core portions of the device structure.
 *
 * @klist_children - klist containing all children of this device
 * @knode_parent - node in sibling list
 * @knode_driver - node in driver list
 * @knode_bus - node in bus list
 * @knode_class - node in class list
 * @deferred_probe - entry in deferred_probe_list which is used to retry the
 *  binding of drivers which were unable to get all the resources needed by
 *  the device; typically because it depends on another driver getting
 *  probed first.
 * @async_driver - pointer to device driver awaiting probe via async_probe
 * @device - pointer back to the struct device that this structure is
 * associated with.
 * @dead - This device is currently either in the process of or has been
 *  removed from the system. Any asynchronous events scheduled for this
 *  device should exit without taking any action.
 *
 * Nothing outside of the driver core should ever touch these fields.
 */
struct device_private {
    struct klist klist_children;
    struct klist_node knode_parent;
    struct klist_node knode_driver;
    struct klist_node knode_bus;
    struct klist_node knode_class;
    struct list_head deferred_probe;
    //struct device_driver *async_driver;
    char *deferred_probe_reason;
    struct device *device;
    u8 dead:1;
};
#define to_device_private_parent(obj)   \
    container_of(obj, struct device_private, knode_parent)
#define to_device_private_bus(obj)  \
    container_of(obj, struct device_private, knode_bus)
#define to_device_private_class(obj)    \
    container_of(obj, struct device_private, knode_class)

struct driver_private {
    struct kobject kobj;
    struct klist klist_devices;
    struct klist_node knode_bus;
    //struct module_kobject *mkobj;
    struct device_driver *driver;
};
#define to_driver(obj) container_of(obj, struct driver_private, kobj)

/* /sys/devices directory */
extern struct kset *devices_kset;

extern int bus_add_device(struct device *dev);

extern int devices_init(void);
extern int buses_init(void);
extern int classes_init(void);

extern int platform_bus_init(void);

extern int bus_add_driver(struct device_driver *drv);
extern void bus_remove_driver(struct device_driver *drv);

extern void module_add_driver(struct module *mod, struct device_driver *drv);
extern void module_remove_driver(struct device_driver *drv);

static inline int driver_match_device(struct device_driver *drv,
                                      struct device *dev)
{
    return drv->bus->match ? drv->bus->match(dev, drv) : 1;
}

extern void bus_probe_device(struct device *dev);

extern void bus_remove_device(struct device *dev);

extern int classes_init(void);

extern int devres_release_all(struct device *dev);
