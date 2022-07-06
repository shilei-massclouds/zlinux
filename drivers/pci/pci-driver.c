// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2002-2004, 2007 Greg Kroah-Hartman <greg@kroah.com>
 * (C) Copyright 2007 Novell Inc.
 */

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
//#include <linux/mempolicy.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
//#include <linux/sched/isolation.h>
#include <linux/cpu.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/suspend.h>
#include <linux/kexec.h>
#endif
#include <linux/of_device.h>
//#include <linux/acpi.h>
#include <linux/dma-map-ops.h>
#if 0
#include "pci.h"
#include "pcie/portdrv.h"
#endif

struct bus_type pci_bus_type = {
    .name       = "pci",
#if 0
    .match      = pci_bus_match,
    .uevent     = pci_uevent,
    .probe      = pci_device_probe,
    .remove     = pci_device_remove,
    .shutdown   = pci_device_shutdown,
    .dev_groups = pci_dev_groups,
    .bus_groups = pci_bus_groups,
    .drv_groups = pci_drv_groups,
    .pm     = PCI_PM_OPS_PTR,
    .num_vf     = pci_bus_num_vf,
    .dma_configure  = pci_dma_configure,
#endif
};
EXPORT_SYMBOL(pci_bus_type);
