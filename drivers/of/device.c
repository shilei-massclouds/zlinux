// SPDX-License-Identifier: GPL-2.0
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#if 0
#include <linux/of_iommu.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-direct.h> /* for bus_dma_region */
#include <linux/dma-map-ops.h>
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include <asm/errno.h>
#include "of_private.h"

int of_device_add(struct platform_device *ofdev)
{
    BUG_ON(ofdev->dev.of_node == NULL);

    /* name and id have to be set so that the platform bus doesn't get
     * confused on matching */
    ofdev->name = dev_name(&ofdev->dev);
    ofdev->id = PLATFORM_DEVID_NONE;

    return device_add(&ofdev->dev);
}
