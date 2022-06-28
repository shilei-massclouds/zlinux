/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * platform_device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _PLATFORM_DEVICE_H_
#define _PLATFORM_DEVICE_H_

#include <linux/device.h>

#define PLATFORM_DEVID_NONE (-1)
#define PLATFORM_DEVID_AUTO (-2)

struct platform_device {
    const char *name;
    int id;
    struct device dev;
    u32 num_resources;
    struct resource *resource;
};

extern struct device platform_bus;

extern struct platform_device *platform_device_alloc(const char *name, int id);

extern void platform_device_put(struct platform_device *pdev);

#endif /* _PLATFORM_DEVICE_H_ */
