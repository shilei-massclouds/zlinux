// SPDX-License-Identifier: GPL-2.0-only
/*
 * OF helpers for IOMMU
 *
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 */

#include <linux/export.h>
#include <linux/iommu.h>
#include <linux/limits.h>
#include <linux/module.h>
#if 0
#include <linux/msi.h>
#endif
#include <linux/of.h>
#include <linux/of_iommu.h>
#if 0
#include <linux/of_pci.h>
#endif
#include <linux/pci.h>
#include <linux/slab.h>
#if 0
#include <linux/fsl/mc.h>
#endif

#define NO_IOMMU    1

static int of_iommu_configure_dev_id(struct device_node *master_np,
                                     struct device *dev, const u32 *id)
{
    panic("%s: END!\n", __func__);
}

static int of_iommu_configure_dev(struct device_node *master_np,
                                  struct device *dev)
{
    struct of_phandle_args iommu_spec;
    int err = NO_IOMMU, idx = 0;

    while (!of_parse_phandle_with_args(master_np, "iommus", "#iommu-cells",
                                       idx, &iommu_spec)) {
        panic("%s: NO iommus!\n", __func__);
    }

    return err;
}

static int of_iommu_configure_device(struct device_node *master_np,
                                     struct device *dev, const u32 *id)
{
    return (id) ? of_iommu_configure_dev_id(master_np, dev, id) :
        of_iommu_configure_dev(master_np, dev);
}

const struct iommu_ops *
of_iommu_configure(struct device *dev,
                   struct device_node *master_np,
                   const u32 *id)
{
    const struct iommu_ops *ops = NULL;
    struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
    int err = NO_IOMMU;

    if (!master_np)
        return NULL;

    if (fwspec) {
        if (fwspec->ops)
            return fwspec->ops;

#if 0
        /* In the deferred case, start again from scratch */
        iommu_fwspec_free(dev);
#endif
    }

    /*
     * We don't currently walk up the tree looking for a parent IOMMU.
     * See the `Notes:' section of
     * Documentation/devicetree/bindings/iommu/iommu.txt
     */
    if (dev_is_pci(dev)) {
        panic("%s: IS PCI!\n", __func__);
    } else {
        err = of_iommu_configure_device(master_np, dev, id);
    }

    /*
     * Two success conditions can be represented by non-negative err here:
     * >0 : there is no IOMMU, or one was unavailable for non-fatal reasons
     *  0 : we found an IOMMU, and dev->fwspec is initialised appropriately
     * <0 : any actual error
     */
    if (!err) {
        /* The fwspec pointer changed, read it again */
        fwspec = dev_iommu_fwspec_get(dev);
        ops    = fwspec->ops;
    }

#if 0
    /*
     * If we have reason to believe the IOMMU driver missed the initial
     * probe for dev, replay it to get things in order.
     */
    if (!err && dev->bus && !device_iommu_mapped(dev))
        err = iommu_probe_device(dev);
#endif

    /* Ignore all other errors apart from EPROBE_DEFER */
    if (err == -EPROBE_DEFER) {
        ops = ERR_PTR(err);
    } else if (err < 0) {
        pr_debug("Adding to IOMMU failed: %d\n", err);
        ops = NULL;
    }

    return ops;
}
