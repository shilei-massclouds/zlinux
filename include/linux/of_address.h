/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OF_ADDRESS_H
#define __OF_ADDRESS_H
#include <linux/ioport.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/io.h>

extern int of_address_to_resource(struct device_node *dev, int index,
                                  struct resource *r);

extern u64 of_translate_address(struct device_node *np, const __be32 *addr);

void __iomem *of_iomap(struct device_node *node, int index);

#endif /* __OF_ADDRESS_H */
