// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt)  "irq: " fmt

#if 0
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#endif
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/topology.h>
#include <linux/slab.h>
#include <linux/smp.h>
#if 0
#include <linux/seq_file.h>
#include <linux/fs.h>
#endif

/**
 * irq_find_matching_fwspec() - Locates a domain for a given fwspec
 * @fwspec: FW specifier for an interrupt
 * @bus_token: domain-specific data
 */
struct irq_domain *
irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                         enum irq_domain_bus_token bus_token)
{
    panic("%s: END!\n", __func__);
}
