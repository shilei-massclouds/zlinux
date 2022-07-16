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
#include <linux/dma-mapping.h>
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

static int platform_probe_fail(struct platform_device *pdev)
{
    return -ENXIO;
}

static int platform_probe(struct device *_dev)
{
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

#if 0
    ret = of_clk_set_defaults(_dev->of_node, false);
    if (ret < 0)
        return ret;

    ret = dev_pm_domain_attach(_dev, true);
    if (ret)
        goto out;
#endif

    if (drv->probe) {
        ret = drv->probe(dev);
#if 0
        if (ret)
            dev_pm_domain_detach(_dev, true);
#endif
    }

 out:
    if (drv->prevent_deferred_probe && ret == -EPROBE_DEFER) {
        pr_warn("probe deferral not supported\n");
        ret = -ENXIO;
    }

    return ret;
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
    pdev->dev.dma_parms = &pdev->dma_parms;

    if (!pdev->dev.coherent_dma_mask)
        pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    if (!pdev->dev.dma_mask) {
        pdev->platform_dma_mask = DMA_BIT_MASK(32);
        pdev->dev.dma_mask = &pdev->platform_dma_mask;
    }
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

/**
 * platform_get_resource - get a resource for a device
 * @dev: platform device
 * @type: resource type
 * @num: resource index
 *
 * Return: a pointer to the resource or NULL on failure.
 */
struct resource *platform_get_resource(struct platform_device *dev,
                                       unsigned int type, unsigned int num)
{
    u32 i;

    for (i = 0; i < dev->num_resources; i++) {
        struct resource *r = &dev->resource[i];

        if (type == resource_type(r) && num-- == 0)
            return r;
    }
    return NULL;
}
EXPORT_SYMBOL_GPL(platform_get_resource);

/**
 * devm_platform_get_and_ioremap_resource - call devm_ioremap_resource() for a
 *                      platform device and get resource
 *
 * @pdev: platform device to use both for memory resource lookup as well as
 *        resource management
 * @index: resource index
 * @res: optional output parameter to store a pointer to the obtained resource.
 *
 * Return: a pointer to the remapped memory or an ERR_PTR() encoded error code
 * on failure.
 */
void __iomem *
devm_platform_get_and_ioremap_resource(struct platform_device *pdev,
                                       unsigned int index,
                                       struct resource **res)
{
    struct resource *r;

    r = platform_get_resource(pdev, IORESOURCE_MEM, index);
    if (res)
        *res = r;
    return devm_ioremap_resource(&pdev->dev, r);
}
EXPORT_SYMBOL_GPL(devm_platform_get_and_ioremap_resource);

/**
 * devm_platform_ioremap_resource - call devm_ioremap_resource() for a platform
 *                  device
 *
 * @pdev: platform device to use both for memory resource lookup as well as
 *        resource management
 * @index: resource index
 *
 * Return: a pointer to the remapped memory or an ERR_PTR() encoded error code
 * on failure.
 */
void __iomem *devm_platform_ioremap_resource(struct platform_device *pdev,
                                             unsigned int index)
{
    return devm_platform_get_and_ioremap_resource(pdev, index, NULL);
}
EXPORT_SYMBOL_GPL(devm_platform_ioremap_resource);

/**
 * platform_get_irq_optional - get an optional IRQ for a device
 * @dev: platform device
 * @num: IRQ number index
 *
 * Gets an IRQ for a platform device. Device drivers should check the return
 * value for errors so as to not pass a negative integer value to the
 * request_irq() APIs. This is the same as platform_get_irq(), except that it
 * does not print an error message if an IRQ can not be obtained.
 *
 * For example::
 *
 *      int irq = platform_get_irq_optional(pdev, 0);
 *      if (irq < 0)
 *          return irq;
 *
 * Return: non-zero IRQ number on success, negative error number on failure.
 */
int platform_get_irq_optional(struct platform_device *dev,
                              unsigned int num)
{
    int ret;
    struct resource *r;

    if (dev->dev.of_node) {
        ret = of_irq_get(dev->dev.of_node, num);
        if (ret > 0 || ret == -EPROBE_DEFER)
            goto out;
    }

    panic("%s: END!\n", __func__);

 out_not_found:
    ret = -ENXIO;

 out:
    WARN(ret == 0, "0 is an invalid IRQ number\n");
    return ret;
}

/**
 * platform_get_irq - get an IRQ for a device
 * @dev: platform device
 * @num: IRQ number index
 *
 * Gets an IRQ for a platform device and prints an error message if finding the
 * IRQ fails. Device drivers should check the return value for errors so as to
 * not pass a negative integer value to the request_irq() APIs.
 *
 * For example::
 *
 *      int irq = platform_get_irq(pdev, 0);
 *      if (irq < 0)
 *          return irq;
 *
 * Return: non-zero IRQ number on success, negative error number on failure.
 */
int platform_get_irq(struct platform_device *dev, unsigned int num)
{
    int ret;

    ret = platform_get_irq_optional(dev, num);
    if (ret < 0)
        return dev_err_probe(&dev->dev, ret,
                             "IRQ index %u not found\n", num);

    return ret;
}
EXPORT_SYMBOL_GPL(platform_get_irq);
