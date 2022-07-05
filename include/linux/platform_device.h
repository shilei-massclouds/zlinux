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

struct platform_device_id;

struct platform_device {
    const char *name;
    int id;
    bool id_auto;
    struct device dev;
#if 0
    u64     platform_dma_mask;
    struct device_dma_parameters dma_parms;
#endif
    u32 num_resources;
    struct resource *resource;

    const struct platform_device_id *id_entry;
    char *driver_override; /* Driver name to force a match */

#if 0
    /* MFD cell pointer */
    struct mfd_cell *mfd_cell;

    /* arch specific additions */
    struct pdev_archdata    archdata;
#endif
};

#define dev_is_platform(dev) ((dev)->bus == &platform_bus_type)
#define to_platform_device(x) container_of((x), struct platform_device, dev)

struct platform_driver {
    int (*probe)(struct platform_device *);
    int (*remove)(struct platform_device *);
    void (*shutdown)(struct platform_device *);
    int (*suspend)(struct platform_device *, pm_message_t state);
    int (*resume)(struct platform_device *);
    struct device_driver driver;
    const struct platform_device_id *id_table;
    bool prevent_deferred_probe;
};

#define to_platform_driver(drv) \
    (container_of((drv), struct platform_driver, driver))

extern struct device platform_bus;

extern struct platform_device *platform_device_alloc(const char *name, int id);

extern void platform_device_put(struct platform_device *pdev);

extern struct bus_type platform_bus_type;

/*
 * use a macro to avoid include chaining to get THIS_MODULE
 */
#define platform_driver_register(drv) \
    __platform_driver_register(drv, THIS_MODULE)
extern int __platform_driver_register(struct platform_driver *,
                                      struct module *);
extern void platform_driver_unregister(struct platform_driver *);

static inline void *platform_get_drvdata(const struct platform_device *pdev)
{
    return dev_get_drvdata(&pdev->dev);
}

#endif /* _PLATFORM_DEVICE_H_ */
