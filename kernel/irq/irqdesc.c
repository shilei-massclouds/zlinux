// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the interrupt descriptor management code. Detailed
 * information is available in Documentation/core-api/genericirq.rst
 *
 */
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/export.h>
#if 0
#include <linux/interrupt.h>
#endif
#include <linux/kernel_stat.h>
#include <linux/radix-tree.h>
#include <linux/bitmap.h>
#include <linux/irqdomain.h>
#include <linux/sysfs.h>

#if 0
#include "internals.h"
#endif

static RADIX_TREE(irq_desc_tree, GFP_KERNEL);

struct irq_desc *irq_to_desc(unsigned int irq)
{
    return radix_tree_lookup(&irq_desc_tree, irq);
}

/**
 * generic_handle_domain_irq - Invoke the handler for a HW irq belonging
 *                             to a domain.
 * @domain: The domain where to perform the lookup
 * @hwirq:  The HW irq number to convert to a logical one
 *
 * Returns: 0 on success, or -EINVAL if conversion has failed
 *
 *      This function must be called from an IRQ context with irq regs
 *      initialized.
 */
int generic_handle_domain_irq(struct irq_domain *domain, unsigned int hwirq)
{
    panic("%s: END!\n", __func__);
#if 0
    return handle_irq_desc(irq_resolve_mapping(domain, hwirq));
#endif
}
EXPORT_SYMBOL_GPL(generic_handle_domain_irq);
