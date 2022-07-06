// SPDX-License-Identifier: GPL-2.0
/*
 * platform.c - platform 'pseudo' bus for legacy devices
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 *
 * Please see Documentation/driver-api/driver-model/platform.rst for more
 * information.
 */

#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#if 0
#include <linux/dma-mapping.h>
#endif
#include <linux/ioport.h>
#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/slab.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>
#endif
#include <linux/pm.h>
#include <linux/idr.h>
#if 0
#include <linux/acpi.h>
#include <linux/clk/clk-conf.h>
#include <linux/limits.h>
#endif
#include <linux/property.h>
#include <linux/types.h>

#include "base.h"

struct platform_object {
    struct platform_device pdev;
    char name[];
};

struct device platform_bus = {
    .init_name  = "platform",
};
EXPORT_SYMBOL_GPL(platform_bus);

static const struct platform_device_id *
platform_match_id(const struct platform_device_id *id,
                  struct platform_device *pdev)
{
    while (id->name[0]) {
        if (strcmp(pdev->name, id->name) == 0) {
            pdev->id_entry = id;
            return id;
        }
        id++;
    }
    return NULL;
}

/**
 * platform_match - bind platform device to platform driver.
 * @dev: device.
 * @drv: driver.
 *
 * Platform device IDs are assumed to be encoded like this:
 * "<name><instance>", where <name> is a short description of the type of
 * device, like "pci" or "floppy", and <instance> is the enumerated
 * instance of the device, like '0' or '42'.  Driver IDs are simply
 * "<name>".  So, extract the <name> from the platform_device structure,
 * and compare it against the name of the driver. Return whether they match
 * or not.
 */
static int platform_match(struct device *dev, struct device_driver *drv)
{
    struct platform_device *pdev = to_platform_device(dev);
    struct platform_driver *pdrv = to_platform_driver(drv);

    /* When driver_override is set, only bind to the matching driver */
    if (pdev->driver_override)
        return !strcmp(pdev->driver_override, drv->name);

    /* Attempt an OF style match first */
    if (of_driver_match_device(dev, drv))
        return 1;

    /* Then try to match against the id table */
    if (pdrv->id_table)
        return platform_match_id(pdrv->id_table, pdev) != NULL;

    /* fall-back to driver name match */
    return (strcmp(pdev->name, drv->name) == 0);
}

static int platform_probe(struct device *_dev)
{
#if 0
    struct platform_driver *drv = to_platform_driver(_dev->driver);
    struct platform_device *dev = to_platform_device(_dev);
    int ret;

    /*
     * A driver registered using platform_driver_probe() cannot be bound
     * again later because the probe function usually lives in __init code
     * and so is gone. For these drivers .probe is set to
     * platform_probe_fail in __platform_driver_probe(). Don't even prepare
     * clocks and PM domains for these to match the traditional behaviour.
     */
    if (unlikely(drv->probe == platform_probe_fail))
        return -ENXIO;

    ret = of_clk_set_defaults(_dev->of_node, false);
    if (ret < 0)
        return ret;

    ret = dev_pm_domain_attach(_dev, true);
    if (ret)
        goto out;

    if (drv->probe) {
        ret = drv->probe(dev);
        if (ret)
            dev_pm_domain_detach(_dev, true);
    }

out:
    if (drv->prevent_deferred_probe && ret == -EPROBE_DEFER) {
        dev_warn(_dev, "probe deferral not supported\n");
        ret = -ENXIO;
    }

    return ret;
#endif
    panic("%s: END!\n", __func__);
}

int platform_dma_configure(struct device *dev)
{
    int ret = 0;

    if (dev->of_node)
        ret = of_dma_configure(dev, dev->of_node, true);

    return ret;
}

struct bus_type platform_bus_type = {
    .name       = "platform",
    //.dev_groups = platform_dev_groups,
    .match      = platform_match,
    //.uevent     = platform_uevent,
    .probe      = platform_probe,
#if 0
    .remove     = platform_remove,
    .shutdown   = platform_shutdown,
#endif
    .dma_configure  = platform_dma_configure,
    //.pm       = &platform_dev_pm_ops,
};
EXPORT_SYMBOL_GPL(platform_bus_type);

static void platform_device_release(struct device *dev)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    struct platform_object *pa =
        container_of(dev, struct platform_object, pdev.dev);

    of_node_put(pa->pdev.dev.of_node);
    kfree(pa->pdev.dev.platform_data);
    kfree(pa->pdev.mfd_cell);
    kfree(pa->pdev.resource);
    kfree(pa->pdev.driver_override);
    kfree(pa);
#endif
}

/*
 * Set up default DMA mask for platform devices if the they weren't
 * previously set by the architecture / DT.
 */
static void setup_pdev_dma_masks(struct platform_device *pdev)
{
    pr_warn("%s: NO implementation!\n", __func__);
#if 0
    pdev->dev.dma_parms = &pdev->dma_parms;

    if (!pdev->dev.coherent_dma_mask)
        pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    if (!pdev->dev.dma_mask) {
        pdev->platform_dma_mask = DMA_BIT_MASK(32);
        pdev->dev.dma_mask = &pdev->platform_dma_mask;
    }
#endif
};

/**
 * platform_device_alloc - create a platform device
 * @name: base name of the device we're adding
 * @id: instance id
 *
 * Create a platform device object which can have other objects attached
 * to it, and which will have attached objects freed when it is released.
 */
struct platform_device *platform_device_alloc(const char *name, int id)
{
    struct platform_object *pa;

    pa = kzalloc(sizeof(*pa) + strlen(name) + 1, GFP_KERNEL);
    if (pa) {
        strcpy(pa->name, name);
        pa->pdev.name = pa->name;
        pa->pdev.id = id;
        device_initialize(&pa->pdev.dev);
        pa->pdev.dev.release = platform_device_release;
        setup_pdev_dma_masks(&pa->pdev);
    }

    return pa ? &pa->pdev : NULL;
}
EXPORT_SYMBOL_GPL(platform_device_alloc);

/**
 * platform_device_put - destroy a platform device
 * @pdev: platform device to free
 *
 * Free all memory associated with a platform device.  This function must
 * _only_ be externally called in error cases.  All other usage is a bug.
 */
void platform_device_put(struct platform_device *pdev)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    if (!IS_ERR_OR_NULL(pdev))
        put_device(&pdev->dev);
#endif
}
EXPORT_SYMBOL_GPL(platform_device_put);

/**
 * __platform_driver_register - register a driver for platform-level devices
 * @drv: platform driver structure
 * @owner: owning module/driver
 */
int __platform_driver_register(struct platform_driver *drv,
                               struct module *owner)
{
    drv->driver.owner = owner;
    drv->driver.bus = &platform_bus_type;

    return driver_register(&drv->driver);
}
EXPORT_SYMBOL_GPL(__platform_driver_register);

/**
 * platform_driver_unregister - unregister a driver for platform-level devices
 * @drv: platform driver structure
 */
void platform_driver_unregister(struct platform_driver *drv)
{
    panic("%s: END!\n", __func__);
    //driver_unregister(&drv->driver);
}
EXPORT_SYMBOL_GPL(platform_driver_unregister);
