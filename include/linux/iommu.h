/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2008 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 */

#ifndef __LINUX_IOMMU_H
#define __LINUX_IOMMU_H

#if 0
#include <linux/scatterlist.h>
#include <linux/ioasid.h>
#endif
#include <linux/device.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/of.h>
#if 0
#include <uapi/linux/iommu.h>
#endif

/**
 * struct iommu_ops - iommu ops and capabilities
 * @capable: check capability
 * @domain_alloc: allocate iommu domain
 * @probe_device: Add device to iommu driver handling
 * @release_device: Remove device from iommu driver handling
 * @probe_finalize: Do final setup work after the device is added to an IOMMU
 *                  group and attached to the groups domain
 * @device_group: find iommu group for a particular device
 * @get_resv_regions: Request list of reserved regions for a device
 * @put_resv_regions: Free list of reserved regions for a device
 * @of_xlate: add OF master IDs to iommu grouping
 * @is_attach_deferred: Check if domain attach should be deferred from iommu
 *                      driver init to device driver init (default no)
 * @dev_has/enable/disable_feat: per device entries to check/enable/disable
 *                               iommu specific features.
 * @dev_feat_enabled: check enabled feature
 * @sva_bind: Bind process address space to device
 * @sva_unbind: Unbind process address space from device
 * @sva_get_pasid: Get PASID associated to a SVA handle
 * @page_response: handle page request response
 * @def_domain_type: device default domain type, return value:
 *      - IOMMU_DOMAIN_IDENTITY: must use an identity domain
 *      - IOMMU_DOMAIN_DMA: must use a dma domain
 *      - 0: use the default setting
 * @default_domain_ops: the default ops for domains
 * @pgsize_bitmap: bitmap of all possible supported page sizes
 * @owner: Driver module providing these ops
 */
struct iommu_ops {
};

/**
 * struct iommu_fwspec - per-device IOMMU instance data
 * @ops: ops for this device's IOMMU
 * @iommu_fwnode: firmware handle for this device's IOMMU
 * @flags: IOMMU_FWSPEC_* flags
 * @num_ids: number of associated device IDs
 * @ids: IDs which this device may present to the IOMMU
 */
struct iommu_fwspec {
    const struct iommu_ops  *ops;
    struct fwnode_handle    *iommu_fwnode;
    u32                     flags;
    unsigned int            num_ids;
    u32                     ids[];
};

/**
 * struct iommu_device - IOMMU core representation of one IOMMU hardware
 *           instance
 * @list: Used by the iommu-core to keep a list of registered iommus
 * @ops: iommu-ops for talking to this iommu
 * @dev: struct device for sysfs handling
 */
struct iommu_device {
    struct list_head list;
    const struct iommu_ops *ops;
    struct fwnode_handle *fwnode;
    struct device *dev;
};

/**
 * struct dev_iommu - Collection of per-device IOMMU data
 *
 * @fault_param: IOMMU detected device fault reporting data
 * @iopf_param:  I/O Page Fault queue and data
 * @fwspec:  IOMMU fwspec data
 * @iommu_dev:   IOMMU device this device is linked to
 * @priv:    IOMMU Driver private data
 *
 * TODO: migrate other per device data pointers under iommu_dev_data, e.g.
 *  struct iommu_group  *iommu_group;
 */
struct dev_iommu {
    struct mutex lock;
#if 0
    struct iommu_fault_param    *fault_param;
    struct iopf_device_param    *iopf_param;
#endif
    struct iommu_fwspec         *fwspec;
    struct iommu_device         *iommu_dev;
    void                        *priv;
};

static inline struct iommu_fwspec *dev_iommu_fwspec_get(struct device *dev)
{
    if (dev->iommu)
        return dev->iommu->fwspec;
    else
        return NULL;
}

#endif /* __LINUX_IOMMU_H */
