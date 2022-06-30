/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __OF_IRQ_H
#define __OF_IRQ_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/ioport.h>
#include <linux/of.h>

typedef int (*of_irq_init_cb_t)(struct device_node *, struct device_node *);

extern int of_irq_count(struct device_node *dev);

extern int of_irq_parse_one(struct device_node *device, int index,
                            struct of_phandle_args *out_irq);

extern int of_irq_to_resource_table(struct device_node *dev,
                                    struct resource *res, int nr_irqs);

extern void of_irq_init(const struct of_device_id *matches);

#endif /* __OF_IRQ_H */
