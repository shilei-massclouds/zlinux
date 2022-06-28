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
#if 0
    struct klist klist_children;
    struct klist_node knode_parent;
    struct klist_node knode_driver;
    struct klist_node knode_bus;
    struct klist_node knode_class;
    struct list_head deferred_probe;
    struct device_driver *async_driver;
    char *deferred_probe_reason;
    struct device *device;
    u8 dead:1;
#endif
};
