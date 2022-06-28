/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQNR_H
#define _LINUX_IRQNR_H

#if 0
#include <uapi/linux/irqnr.h>
#endif

extern int nr_irqs;
extern struct irq_desc *irq_to_desc(unsigned int irq);
unsigned int irq_get_next_irq(unsigned int offset);

#endif /* _LINUX_IRQNR_H */
