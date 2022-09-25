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
    u64 platform_dma_mask;
    struct device_dma_parameters dma_parms;
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

/* module_platform_driver() - Helper macro for drivers that don't do
 * anything special in module init/exit.  This eliminates a lot of
 * boilerplate.  Each module may only use this macro once, and
 * calling it replaces module_init() and module_exit()
 */
#define module_platform_driver(__platform_driver) \
    module_driver(__platform_driver, platform_driver_register, \
                  platform_driver_unregister)

static inline void *platform_get_drvdata(const struct platform_device *pdev)
{
    return dev_get_drvdata(&pdev->dev);
}

static inline void platform_set_drvdata(struct platform_device *pdev,
                                        void *data)
{
    dev_set_drvdata(&pdev->dev, data);
}

extern void __iomem *
devm_platform_get_and_ioremap_resource(struct platform_device *pdev,
                                       unsigned int index,
                                       struct resource **res);

extern void __iomem *
devm_platform_ioremap_resource(struct platform_device *pdev,
                               unsigned int index);

extern int platform_get_irq(struct platform_device *, unsigned int);
extern int platform_get_irq_optional(struct platform_device *,
                                     unsigned int);

extern struct platform_device *
platform_device_alloc(const char *name, int id);
extern int platform_device_add_resources(struct platform_device *pdev,
                                         const struct resource *res,
                                         unsigned int num);
extern int platform_device_add_data(struct platform_device *pdev,
                                    const void *data, size_t size);
extern int platform_device_add(struct platform_device *pdev);
extern void platform_device_del(struct platform_device *pdev);

#endif /* _PLATFORM_DEVICE_H_ */
