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

static LIST_HEAD(irq_domain_list);
static DEFINE_MUTEX(irq_domain_mutex);

/**
 * irq_find_matching_fwspec() - Locates a domain for a given fwspec
 * @fwspec: FW specifier for an interrupt
 * @bus_token: domain-specific data
 */
struct irq_domain *
irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                         enum irq_domain_bus_token bus_token)
{
    struct irq_domain *h, *found = NULL;
    struct fwnode_handle *fwnode = fwspec->fwnode;
    int rc;

    /* We might want to match the legacy controller last since
     * it might potentially be set to match all interrupts in
     * the absence of a device node. This isn't a problem so far
     * yet though...
     *
     * bus_token == DOMAIN_BUS_ANY matches any domain, any other
     * values must generate an exact match for the domain to be
     * selected.
     */
    mutex_lock(&irq_domain_mutex);
    list_for_each_entry(h, &irq_domain_list, link) {
        panic("%s: NO!\n", __func__);
    }
    mutex_unlock(&irq_domain_mutex);

    return found;
}
