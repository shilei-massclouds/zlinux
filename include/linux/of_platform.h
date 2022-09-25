/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_OF_PLATFORM_H
#define _LINUX_OF_PLATFORM_H
/*
 *    Copyright (C) 2006 Benjamin Herrenschmidt, IBM Corp.
 *           <benh@kernel.crashing.org>
 */

#include <linux/device.h>
#include <linux/mod_devicetable.h>
#if 0
#include <linux/pm.h>
#endif
#include <linux/of_device.h>
#include <linux/platform_device.h>

/**
 * struct of_dev_auxdata - lookup table entry for device names & platform_data
 * @compatible: compatible value of node to match against node
 * @phys_addr: Start address of registers to match against node
 * @name: Name to assign for matching nodes
 * @platform_data: platform_data to assign for matching nodes
 *
 * This lookup table allows the caller of of_platform_populate() to override
 * the names of devices when creating devices from the device tree.  The table
 * should be terminated with an empty entry.  It also allows the platform_data
 * pointer to be set.
 *
 * The reason for this functionality is that some Linux infrastructure uses
 * the device name to look up a specific device, but the Linux-specific names
 * are not encoded into the device tree, so the kernel needs to provide specific
 * values.
 *
 * Note: Using an auxdata lookup table should be considered a last resort when
 * converting a platform to use the DT.  Normally the automatically generated
 * device name will not matter, and drivers should obtain data from the device
 * node instead of from an anonymous platform_data pointer.
 */
struct of_dev_auxdata {
    char *compatible;
    resource_size_t phys_addr;
    char *name;
    void *platform_data;
};

#endif  /* _LINUX_OF_PLATFORM_H */
