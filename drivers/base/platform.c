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
#if 0
#include <linux/of_device.h>
#include <linux/of_irq.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#if 0
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/dma-mapping.h>
#endif
#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/slab.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>
#endif
#include <linux/idr.h>
#if 0
#include <linux/acpi.h>
#include <linux/clk/clk-conf.h>
#include <linux/limits.h>
#include <linux/property.h>
#endif
#include <linux/types.h>

#if 0
#include "base.h"
#endif
//#include "power/power.h"

struct platform_object {
    struct platform_device pdev;
    char name[];
};

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
    panic("%s: NO implementation!\n", __func__);
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
