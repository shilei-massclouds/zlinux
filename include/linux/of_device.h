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

extern const struct of_device_id *
of_match_device(const struct of_device_id *matches, const struct device *dev);

/**
 * of_driver_match_device - Tell if a driver's of_match_table matches a device.
 * @drv: the device_driver structure to test
 * @dev: the device structure to match against
 */
static inline int of_driver_match_device(struct device *dev,
                                         const struct device_driver *drv)
{
    return of_match_device(drv->of_match_table, dev) != NULL;
}

int of_dma_configure_id(struct device *dev, struct device_node *np,
                        bool force_dma, const u32 *id);

static inline int of_dma_configure(struct device *dev, struct device_node *np,
                                   bool force_dma)
{
    return of_dma_configure_id(dev, np, force_dma, NULL);
}

#endif /* _LINUX_OF_DEVICE_H */
