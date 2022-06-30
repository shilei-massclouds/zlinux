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

struct irqchip_fwid {
    struct fwnode_handle    fwnode;
    unsigned int            type;
    char                    *name;
    phys_addr_t             *pa;
};

static const char *irqchip_fwnode_get_name(const struct fwnode_handle *fwnode)
{
    struct irqchip_fwid *fwid =
        container_of(fwnode, struct irqchip_fwid, fwnode);

    return fwid->name;
}

const struct fwnode_operations irqchip_fwnode_ops = {
    .get_name = irqchip_fwnode_get_name,
};
EXPORT_SYMBOL_GPL(irqchip_fwnode_ops);

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

/**
 * irq_domain_xlate_onecell() - Generic xlate for direct one cell bindings
 *
 * Device Tree IRQ specifier translation function which works with one cell
 * bindings where the cell value maps directly to the hwirq number.
 */
int irq_domain_xlate_onecell(struct irq_domain *d, struct device_node *ctrlr,
                             const u32 *intspec, unsigned int intsize,
                             unsigned long *out_hwirq, unsigned int *out_type)
{
    if (WARN_ON(intsize < 1))
        return -EINVAL;
    *out_hwirq = intspec[0];
    *out_type = IRQ_TYPE_NONE;
    return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_xlate_onecell);

static void irq_domain_check_hierarchy(struct irq_domain *domain)
{
    /* Hierarchy irq_domains must implement callback alloc() */
    if (domain->ops->alloc)
        domain->flags |= IRQ_DOMAIN_FLAG_HIERARCHY;
}

/**
 * __irq_domain_add() - Allocate a new irq_domain data structure
 * @fwnode: firmware node for the interrupt controller
 * @size: Size of linear map; 0 for radix mapping only
 * @hwirq_max: Maximum number of interrupts supported by controller
 * @direct_max: Maximum value of direct maps; Use ~0 for no limit; 0 for no
 *              direct mapping
 * @ops: domain callbacks
 * @host_data: Controller private data pointer
 *
 * Allocates and initializes an irq_domain structure.
 * Returns pointer to IRQ domain, or NULL on failure.
 */
struct irq_domain *
__irq_domain_add(struct fwnode_handle *fwnode, unsigned int size,
                 irq_hw_number_t hwirq_max, int direct_max,
                 const struct irq_domain_ops *ops,
                 void *host_data)
{
    struct irqchip_fwid *fwid;
    struct irq_domain *domain;

    static atomic_t unknown_domains;

    if (WARN_ON(direct_max))
        return NULL;

    domain = kzalloc_node(struct_size(domain, revmap, size),
                          GFP_KERNEL, of_node_to_nid(to_of_node(fwnode)));
    if (!domain)
        return NULL;

    if (is_fwnode_irqchip(fwnode)) {
        panic("%s: fwnode!\n", __func__);
#if 0
        fwid = container_of(fwnode, struct irqchip_fwid, fwnode);

        switch (fwid->type) {
        case IRQCHIP_FWNODE_NAMED:
        case IRQCHIP_FWNODE_NAMED_ID:
            domain->fwnode = fwnode;
            domain->name = kstrdup(fwid->name, GFP_KERNEL);
            if (!domain->name) {
                kfree(domain);
                return NULL;
            }
            domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
            break;
        default:
            domain->fwnode = fwnode;
            domain->name = fwid->name;
            break;
        }
#endif
    } else if (is_of_node(fwnode) || is_software_node(fwnode)) {
        char *name;

        /*
         * fwnode paths contain '/', which debugfs is legitimately
         * unhappy about. Replace them with ':', which does
         * the trick and is not as offensive as '\'...
         */
        name = kasprintf(GFP_KERNEL, "%pfw", fwnode);
        if (!name) {
            kfree(domain);
            return NULL;
        }

        strreplace(name, '/', ':');

        domain->name = name;
        domain->fwnode = fwnode;
        domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
    }

    if (!domain->name) {
        if (fwnode)
            pr_err("Invalid fwnode type for irqdomain\n");
        domain->name = kasprintf(GFP_KERNEL, "unknown-%d",
                                 atomic_inc_return(&unknown_domains));
        if (!domain->name) {
            kfree(domain);
            return NULL;
        }
        domain->flags |= IRQ_DOMAIN_NAME_ALLOCATED;
    }

    fwnode_handle_get(fwnode);
    fwnode_dev_initialized(fwnode, true);

    /* Fill structure */
    INIT_RADIX_TREE(&domain->revmap_tree, GFP_KERNEL);
    mutex_init(&domain->revmap_mutex);
    domain->ops = ops;
    domain->host_data = host_data;
    domain->hwirq_max = hwirq_max;

    if (direct_max) {
        size = direct_max;
        domain->flags |= IRQ_DOMAIN_FLAG_NO_MAP;
    }

    domain->revmap_size = size;

    irq_domain_check_hierarchy(domain);

    mutex_lock(&irq_domain_mutex);
    list_add(&domain->link, &irq_domain_list);
    mutex_unlock(&irq_domain_mutex);

    pr_info("Added domain %s\n", domain->name);
    return domain;
}
EXPORT_SYMBOL_GPL(__irq_domain_add);
