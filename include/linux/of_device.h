/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OF_DEVICE_H
#define _LINUX_OF_DEVICE_H

#include <linux/cpu.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h> /* temporary until merge */

#include <linux/of.h>
#include <linux/mod_devicetable.h>

struct device;

extern int of_device_add(struct platform_device *pdev);

#endif /* _LINUX_OF_DEVICE_H */
