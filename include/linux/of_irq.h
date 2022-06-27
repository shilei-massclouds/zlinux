/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OF_IRQ_H
#define __OF_IRQ_H

#include <linux/types.h>
#include <linux/errno.h>
#if 0
#include <linux/irq.h>
#include <linux/irqdomain.h>
#endif
#include <linux/ioport.h>
#include <linux/of.h>

extern int of_irq_count(struct device_node *dev);

extern int of_irq_parse_one(struct device_node *device, int index,
                            struct of_phandle_args *out_irq);

#endif /* __OF_IRQ_H */
