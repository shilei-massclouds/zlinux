// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)    "iommu: " fmt

#include <linux/device.h>
#include <linux/dma-iommu.h>
#include <linux/kernel.h>
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/iommu.h>
#include <linux/idr.h>
#include <linux/notifier.h>
#include <linux/err.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/property.h>
#include <linux/fsl/mc.h>
#include <linux/module.h>
#include <linux/cc_platform.h>
#include <trace/events/iommu.h>

void iommu_fwspec_free(struct device *dev)
{
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

    if (fwspec) {
        fwnode_handle_put(fwspec->iommu_fwnode);
        kfree(fwspec);
        dev_iommu_fwspec_set(dev, NULL);
    }
}
EXPORT_SYMBOL_GPL(iommu_fwspec_free);
