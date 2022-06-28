/* SPDX-License-Identifier: GPL-2.0 */
/*
 * irq_domain - IRQ translation domains
 *
 * Translation infrastructure between hw and linux irq numbers.  This is
 * helpful for interrupt controllers to implement mapping between hardware
 * irq numbers and the Linux irq number space.
 *
 * irq_domains also have hooks for translating device tree or other
 * firmware interrupt representations into a hardware irq number that
 * can be mapped back to a Linux irq number without any extra platform
 * support code.
 *
 * Interrupt controller "domain" data structure. This could be defined as a
 * irq domain controller. That is, it handles the mapping between hardware
 * and virtual interrupt numbers for a given interrupt domain. The domain
 * structure is generally created by the PIC code for a given PIC instance
 * (though a domain can cover more than one PIC if they have a flat number
 * model). It's the domain callbacks that are responsible for setting the
 * irq_chip on a given irq_desc after it's been mapped.
 *
 * The host code and data structures use a fwnode_handle pointer to
 * identify the domain. In some cases, and in order to preserve source
 * code compatibility, this fwnode pointer is "upgraded" to a DT
 * device_node. For those firmware infrastructures that do not provide
 * a unique identifier for an interrupt controller, the irq_domain
 * code offers a fwnode allocator.
 */
#ifndef _LINUX_IRQDOMAIN_H
#define _LINUX_IRQDOMAIN_H

#include <linux/types.h>
#if 0
#include <linux/irqhandler.h>
#endif
#include <linux/of.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>

struct device_node;
struct fwnode_handle;
struct irq_domain;
struct irq_chip;
struct irq_data;
struct irq_desc;
struct cpumask;
struct seq_file;
struct irq_affinity_desc;

/*
 * Should several domains have the same device node, but serve
 * different purposes (for example one domain is for PCI/MSI, and the
 * other for wired IRQs), they can be distinguished using a
 * bus-specific token. Most domains are expected to only carry
 * DOMAIN_BUS_ANY.
 */
enum irq_domain_bus_token {
    DOMAIN_BUS_ANY      = 0,
    DOMAIN_BUS_WIRED,
    DOMAIN_BUS_GENERIC_MSI,
    DOMAIN_BUS_PCI_MSI,
    DOMAIN_BUS_PLATFORM_MSI,
    DOMAIN_BUS_NEXUS,
    DOMAIN_BUS_IPI,
    DOMAIN_BUS_FSL_MC_MSI,
    DOMAIN_BUS_TI_SCI_INTA_MSI,
    DOMAIN_BUS_WAKEUP,
    DOMAIN_BUS_VMD_MSI,
};

#define IRQ_DOMAIN_IRQ_SPEC_PARAMS 16

/**
 * struct irq_fwspec - generic IRQ specifier structure
 *
 * @fwnode:     Pointer to a firmware-specific descriptor
 * @param_count:    Number of device-specific parameters
 * @param:      Device-specific parameters
 *
 * This structure, directly modeled after of_phandle_args, is used to
 * pass a device-specific description of an interrupt.
 */
struct irq_fwspec {
    struct fwnode_handle *fwnode;
    int param_count;
    u32 param[IRQ_DOMAIN_IRQ_SPEC_PARAMS];
};

/**
 * struct irq_domain - Hardware interrupt number translation object
 * @link: Element in global irq_domain list.
 * @name: Name of interrupt domain
 * @ops: pointer to irq_domain methods
 * @host_data: private data pointer for use by owner.  Not touched by irq_domain
 *             core code.
 * @flags: host per irq_domain flags
 * @mapcount: The number of mapped interrupts
 *
 * Optional elements
 * @fwnode: Pointer to firmware node associated with the irq_domain. Pretty easy
 *          to swap it for the of_node via the irq_domain_get_of_node accessor
 * @gc: Pointer to a list of generic chips. There is a helper function for
 *      setting up one or more generic chips for interrupt controllers
 *      drivers using the generic chip library which uses this pointer.
 * @dev: Pointer to a device that the domain represent, and that will be
 *       used for power management purposes.
 * @parent: Pointer to parent irq_domain to support hierarchy irq_domains
 *
 * Revmap data, used internally by irq_domain
 * @revmap_size: Size of the linear map table @revmap[]
 * @revmap_tree: Radix map tree for hwirqs that don't fit in the linear map
 * @revmap_mutex: Lock for the revmap
 * @revmap: Linear table of irq_data pointers
 */
struct irq_domain {
#if 0
    struct list_head link;
    const char *name;
    const struct irq_domain_ops *ops;
    void *host_data;
    unsigned int flags;
    unsigned int mapcount;

    /* Optional data */
    struct fwnode_handle *fwnode;
    enum irq_domain_bus_token bus_token;
    struct irq_domain_chip_generic *gc;
    struct device *dev;
    struct irq_domain *parent;

    /* reverse map data. The linear map gets appended to the irq_domain */
    irq_hw_number_t hwirq_max;
    unsigned int revmap_size;
    struct radix_tree_root revmap_tree;
    struct mutex revmap_mutex;
    struct irq_data __rcu *revmap[];
#endif
};

extern struct irq_domain *
irq_find_matching_fwspec(struct irq_fwspec *fwspec,
                         enum irq_domain_bus_token bus_token);

static inline
struct irq_domain *irq_find_matching_fwnode(struct fwnode_handle *fwnode,
                                            enum irq_domain_bus_token bus_token)
{
    struct irq_fwspec fwspec = {
        .fwnode = fwnode,
    };

    return irq_find_matching_fwspec(&fwspec, bus_token);
}

static inline struct fwnode_handle *of_node_to_fwnode(struct device_node *node)
{
    return node ? &node->fwnode : NULL;
}

static inline struct irq_domain *
irq_find_matching_host(struct device_node *node,
                       enum irq_domain_bus_token bus_token)
{
    return irq_find_matching_fwnode(of_node_to_fwnode(node), bus_token);
}

static inline struct irq_domain *irq_find_host(struct device_node *node)
{
    struct irq_domain *d;

    d = irq_find_matching_host(node, DOMAIN_BUS_WIRED);
    if (!d)
        d = irq_find_matching_host(node, DOMAIN_BUS_ANY);

    return d;
}

#endif /* _LINUX_IRQDOMAIN_H */
