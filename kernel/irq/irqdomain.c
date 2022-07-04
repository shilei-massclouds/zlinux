// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt)  "irq: " fmt

#if 0
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/irqdesc.h>
#endif
#include <linux/irq.h>
#include <linux/interrupt.h>
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

static struct irq_domain *irq_default_domain;

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
        if (h->ops->select && fwspec->param_count)
            rc = h->ops->select(h, fwspec, bus_token);
        else if (h->ops->match)
            rc = h->ops->match(h, to_of_node(fwnode), bus_token);
        else
            rc = ((fwnode != NULL) && (h->fwnode == fwnode) &&
                  ((bus_token == DOMAIN_BUS_ANY) ||
                   (h->bus_token == bus_token)));

        if (rc) {
            found = h;
            break;
        }
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

void of_phandle_args_to_fwspec(struct device_node *np, const u32 *args,
                               unsigned int count, struct irq_fwspec *fwspec)
{
    int i;

    fwspec->fwnode = of_node_to_fwnode(np);
    fwspec->param_count = count;

    for (i = 0; i < count; i++)
        fwspec->param[i] = args[i];
}
EXPORT_SYMBOL_GPL(of_phandle_args_to_fwspec);

static int irq_domain_translate(struct irq_domain *d,
                                struct irq_fwspec *fwspec,
                                irq_hw_number_t *hwirq, unsigned int *type)
{
    if (d->ops->translate)
        return d->ops->translate(d, fwspec, hwirq, type);
    if (d->ops->xlate)
        return d->ops->xlate(d, to_of_node(fwspec->fwnode),
                             fwspec->param, fwspec->param_count,
                             hwirq, type);

    /* If domain has no translation, then we assume interrupt line */
    *hwirq = fwspec->param[0];
    return 0;
}

/**
 * irq_domain_free_irqs - Free IRQ number and associated data structures
 * @virq:   base IRQ number
 * @nr_irqs:    number of IRQs to free
 */
void irq_domain_free_irqs(unsigned int virq, unsigned int nr_irqs)
{
    panic("%s: END!\n", __func__);
#if 0
    struct irq_data *data = irq_get_irq_data(virq);
    int i;

    if (WARN(!data || !data->domain || !data->domain->ops->free,
             "NULL pointer, cannot free irq\n"))
        return;

    mutex_lock(&irq_domain_mutex);
    for (i = 0; i < nr_irqs; i++)
        irq_domain_remove_irq(virq + i);
    irq_domain_free_irqs_hierarchy(data->domain, virq, nr_irqs);
    mutex_unlock(&irq_domain_mutex);

    irq_domain_free_irq_data(virq, nr_irqs);
    irq_free_descs(virq, nr_irqs);
#endif
}

/**
 * irq_dispose_mapping() - Unmap an interrupt
 * @virq: linux irq number of the interrupt to unmap
 */
void irq_dispose_mapping(unsigned int virq)
{
    panic("%s: END!\n", __func__);
#if 0
    struct irq_data *irq_data = irq_get_irq_data(virq);
    struct irq_domain *domain;

    if (!virq || !irq_data)
        return;

    domain = irq_data->domain;
    if (WARN_ON(domain == NULL))
        return;

    if (irq_domain_is_hierarchy(domain)) {
        irq_domain_free_irqs(virq, 1);
    } else {
        irq_domain_disassociate(domain, virq);
        irq_free_desc(virq);
    }
#endif
}
EXPORT_SYMBOL_GPL(irq_dispose_mapping);

unsigned int irq_create_fwspec_mapping(struct irq_fwspec *fwspec)
{
    struct irq_domain *domain;
    struct irq_data *irq_data;
    irq_hw_number_t hwirq;
    unsigned int type = IRQ_TYPE_NONE;
    int virq;

    if (fwspec->fwnode) {
        domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_WIRED);
        if (!domain)
            domain = irq_find_matching_fwspec(fwspec, DOMAIN_BUS_ANY);
    } else {
        domain = irq_default_domain;
    }

    if (!domain) {
        pr_warn("no irq domain found for %s !\n",
                of_node_full_name(to_of_node(fwspec->fwnode)));
        return 0;
    }

    if (irq_domain_translate(domain, fwspec, &hwirq, &type))
        return 0;

    /*
     * WARN if the irqchip returns a type with bits
     * outside the sense mask set and clear these bits.
     */
    if (WARN_ON(type & ~IRQ_TYPE_SENSE_MASK))
        type &= IRQ_TYPE_SENSE_MASK;

    /*
     * If we've already configured this interrupt,
     * don't do it again, or hell will break loose.
     */
    virq = irq_find_mapping(domain, hwirq);
    if (virq) {
        panic("%s: has virq!\n", __func__);
#if 0
        /*
         * If the trigger type is not specified or matches the
         * current trigger type then we are done so return the
         * interrupt number.
         */
        if (type == IRQ_TYPE_NONE || type == irq_get_trigger_type(virq))
            return virq;

        /*
         * If the trigger type has not been set yet, then set
         * it now and return the interrupt number.
         */
        if (irq_get_trigger_type(virq) == IRQ_TYPE_NONE) {
            irq_data = irq_get_irq_data(virq);
            if (!irq_data)
                return 0;

            irqd_set_trigger_type(irq_data, type);
            return virq;
        }

        pr_warn("type mismatch, failed to map hwirq-%lu for %s!\n",
            hwirq, of_node_full_name(to_of_node(fwspec->fwnode)));
        return 0;
#endif
    }

    if (irq_domain_is_hierarchy(domain)) {
        virq = irq_domain_alloc_irqs(domain, 1, NUMA_NO_NODE, fwspec);
        if (virq <= 0)
            return 0;
    } else {
        /* Create mapping */
        virq = irq_create_mapping(domain, hwirq);
        if (!virq)
            return virq;
    }

    irq_data = irq_get_irq_data(virq);
    if (!irq_data) {
        if (irq_domain_is_hierarchy(domain))
            irq_domain_free_irqs(virq, 1);
        else
            irq_dispose_mapping(virq);
        return 0;
    }

    /* Store trigger type */
    irqd_set_trigger_type(irq_data, type);

    return virq;
}

unsigned int irq_create_of_mapping(struct of_phandle_args *irq_data)
{
    struct irq_fwspec fwspec;

    of_phandle_args_to_fwspec(irq_data->np, irq_data->args,
                              irq_data->args_count, &fwspec);

    return irq_create_fwspec_mapping(&fwspec);
}
EXPORT_SYMBOL_GPL(irq_create_of_mapping);

/**
 * __irq_resolve_mapping() - Find a linux irq from a hw irq number.
 * @domain: domain owning this hardware interrupt
 * @hwirq: hardware irq number in that domain space
 * @irq: optional pointer to return the Linux irq if required
 *
 * Returns the interrupt descriptor.
 */
struct irq_desc *
__irq_resolve_mapping(struct irq_domain *domain,
                      irq_hw_number_t hwirq,
                      unsigned int *irq)
{
    struct irq_desc *desc = NULL;
    struct irq_data *data;

    /* Look for default domain if necessary */
    if (domain == NULL)
        domain = irq_default_domain;
    if (domain == NULL)
        return desc;

    rcu_read_lock();
    /* Check if the hwirq is in the linear revmap. */
    if (hwirq < domain->revmap_size)
        data = rcu_dereference(domain->revmap[hwirq]);
    else
        data = radix_tree_lookup(&domain->revmap_tree, hwirq);

    if (likely(data)) {
        panic("%s: has data!\n", __func__);
#if 0
        desc = irq_data_to_desc(data);
        if (irq)
            *irq = data->irq;
#endif
    }

    rcu_read_unlock();
    return desc;
}
EXPORT_SYMBOL_GPL(__irq_resolve_mapping);

int irq_domain_alloc_descs(int virq, unsigned int cnt, irq_hw_number_t hwirq,
                           int node, const struct irq_affinity_desc *affinity)
{
    unsigned int hint;

    if (virq >= 0) {
        virq = __irq_alloc_descs(virq, virq, cnt, node, THIS_MODULE, affinity);
    } else {
        hint = hwirq % nr_irqs;
        if (hint == 0)
            hint++;
        virq = __irq_alloc_descs(-1, hint, cnt, node, THIS_MODULE, affinity);
        if (virq <= 0 && hint > 1) {
            virq = __irq_alloc_descs(-1, 1, cnt, node, THIS_MODULE, affinity);
        }
    }

    return virq;
}

static void irq_domain_set_mapping(struct irq_domain *domain,
                                   irq_hw_number_t hwirq,
                                   struct irq_data *irq_data)
{
    mutex_lock(&domain->revmap_mutex);
    if (hwirq < domain->revmap_size)
        rcu_assign_pointer(domain->revmap[hwirq], irq_data);
    else
        radix_tree_insert(&domain->revmap_tree, hwirq, irq_data);
    mutex_unlock(&domain->revmap_mutex);
}

int irq_domain_associate(struct irq_domain *domain,
                         unsigned int virq,
                         irq_hw_number_t hwirq)
{
    int ret;
    struct irq_data *irq_data = irq_get_irq_data(virq);

    pr_info("%s: (%u:%lu max:%lu) ...\n",
            __func__, virq, hwirq, domain->hwirq_max);

    if (WARN(hwirq >= domain->hwirq_max,
             "error: hwirq 0x%x is too large for %s\n",
             (int)hwirq, domain->name))
        return -EINVAL;
    if (WARN(!irq_data, "error: virq%i is not allocated", virq))
        return -EINVAL;
    if (WARN(irq_data->domain, "error: virq%i is already associated", virq))
        return -EINVAL;

    mutex_lock(&irq_domain_mutex);
    irq_data->hwirq = hwirq;
    irq_data->domain = domain;
    if (domain->ops->map) {
        ret = domain->ops->map(domain, virq, hwirq);
        if (ret != 0) {
            /*
             * If map() returns -EPERM, this interrupt is protected
             * by the firmware or some other service and shall not
             * be mapped. Don't bother telling the user about it.
             */
            if (ret != -EPERM) {
                pr_info("%s didn't like hwirq-0x%lx to VIRQ%i mapping(rc=%d)\n",
                        domain->name, hwirq, virq, ret);
            }
            irq_data->domain = NULL;
            irq_data->hwirq = 0;
            mutex_unlock(&irq_domain_mutex);
            return ret;
        }

        /* If not already assigned, give the domain the chip's name */
        if (!domain->name && irq_data->chip)
            domain->name = irq_data->chip->name;
    }

    domain->mapcount++;
    irq_domain_set_mapping(domain, hwirq, irq_data);
    mutex_unlock(&irq_domain_mutex);

    irq_clear_status_flags(virq, IRQ_NOREQUEST);

    return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_associate);

/**
 * irq_create_mapping_affinity() - Map a hardware interrupt into linux irq space
 * @domain: domain owning this hardware interrupt or NULL for default domain
 * @hwirq: hardware irq number in that domain space
 * @affinity: irq affinity
 *
 * Only one mapping per hardware interrupt is permitted. Returns a linux
 * irq number.
 * If the sense/trigger is to be specified, set_irq_type() should be called
 * on the number returned from that call.
 */
unsigned int
irq_create_mapping_affinity(struct irq_domain *domain,
                            irq_hw_number_t hwirq,
                            const struct irq_affinity_desc *affinity)
{
    struct device_node *of_node;
    int virq;

    pr_info("irq_create_mapping(0x%p, 0x%lx)\n", domain, hwirq);

    /* Look for default domain if necessary */
    if (domain == NULL)
        domain = irq_default_domain;
    if (domain == NULL) {
        WARN(1, "%s(, %lx) called with NULL domain\n", __func__, hwirq);
        return 0;
    }
    pr_info("-> using domain @%p\n", domain);

    of_node = irq_domain_get_of_node(domain);

    /* Check if mapping already exists */
    virq = irq_find_mapping(domain, hwirq);
    if (virq) {
        pr_debug("-> existing mapping on virq %d\n", virq);
        return virq;
    }

    /* Allocate a virtual interrupt number */
    virq = irq_domain_alloc_descs(-1, 1, hwirq, of_node_to_nid(of_node),
                                  affinity);
    if (virq <= 0) {
        pr_debug("-> virq allocation failed\n");
        return 0;
    }

    if (irq_domain_associate(domain, virq, hwirq)) {
        irq_free_desc(virq);
        return 0;
    }

    pr_info("irq %lu on domain %s mapped to virtual irq %u\n",
            hwirq, of_node_full_name(of_node), virq);

    return virq;
}
EXPORT_SYMBOL_GPL(irq_create_mapping_affinity);

/**
 * irq_domain_get_irq_data - Get irq_data associated with @virq and @domain
 * @domain: domain to match
 * @virq:   IRQ number to get irq_data
 */
struct irq_data *
irq_domain_get_irq_data(struct irq_domain *domain, unsigned int virq)
{
    struct irq_data *irq_data;

    for (irq_data = irq_get_irq_data(virq);
         irq_data;
         irq_data = irq_data->parent_data)
        if (irq_data->domain == domain)
            return irq_data;

    return NULL;
}
EXPORT_SYMBOL_GPL(irq_domain_get_irq_data);

/**
 * irq_domain_set_hwirq_and_chip - Set hwirq and irqchip of @virq at @domain
 * @domain: Interrupt domain to match
 * @virq:   IRQ number
 * @hwirq:  The hwirq number
 * @chip:   The associated interrupt chip
 * @chip_data:  The associated chip data
 */
int irq_domain_set_hwirq_and_chip(struct irq_domain *domain,
                                  unsigned int virq, irq_hw_number_t hwirq,
                                  const struct irq_chip *chip, void *chip_data)
{
    struct irq_data *irq_data = irq_domain_get_irq_data(domain, virq);

    if (!irq_data)
        return -ENOENT;

    irq_data->hwirq = hwirq;
    irq_data->chip = (struct irq_chip *)(chip ? chip : &no_irq_chip);
    irq_data->chip_data = chip_data;

    return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_set_hwirq_and_chip);

/**
 * irq_domain_set_info - Set the complete data for a @virq in @domain
 * @domain:     Interrupt domain to match
 * @virq:       IRQ number
 * @hwirq:      The hardware interrupt number
 * @chip:       The associated interrupt chip
 * @chip_data:      The associated interrupt chip data
 * @handler:        The interrupt flow handler
 * @handler_data:   The interrupt flow handler data
 * @handler_name:   The interrupt handler name
 */
void irq_domain_set_info(struct irq_domain *domain,
                         unsigned int virq, irq_hw_number_t hwirq,
                         const struct irq_chip *chip, void *chip_data,
                         irq_flow_handler_t handler, void *handler_data,
                         const char *handler_name)
{
    irq_domain_set_hwirq_and_chip(domain, virq, hwirq, chip, chip_data);
    __irq_set_handler(virq, handler, 0, handler_name);
    irq_set_handler_data(virq, handler_data);
}
EXPORT_SYMBOL(irq_domain_set_info);

static void __irq_domain_deactivate_irq(struct irq_data *irq_data)
{
    if (irq_data && irq_data->domain) {
        struct irq_domain *domain = irq_data->domain;

        if (domain->ops->deactivate)
            domain->ops->deactivate(domain, irq_data);
        if (irq_data->parent_data)
            __irq_domain_deactivate_irq(irq_data->parent_data);
    }
}

static int __irq_domain_activate_irq(struct irq_data *irqd, bool reserve)
{
    int ret = 0;

    if (irqd && irqd->domain) {
        struct irq_domain *domain = irqd->domain;

        if (irqd->parent_data)
            ret = __irq_domain_activate_irq(irqd->parent_data,
                            reserve);
        if (!ret && domain->ops->activate) {
            ret = domain->ops->activate(domain, irqd, reserve);
            /* Rollback in case of error */
            if (ret && irqd->parent_data)
                __irq_domain_deactivate_irq(irqd->parent_data);
        }
    }
    return ret;
}

/**
 * irq_domain_activate_irq - Call domain_ops->activate recursively to activate
 *               interrupt
 * @irq_data:   Outermost irq_data associated with interrupt
 * @reserve:    If set only reserve an interrupt vector instead of assigning one
 *
 * This is the second step to call domain_ops->activate to program interrupt
 * controllers, so the interrupt could actually get delivered.
 */
int irq_domain_activate_irq(struct irq_data *irq_data, bool reserve)
{
    int ret = 0;

    if (!irqd_is_activated(irq_data))
        ret = __irq_domain_activate_irq(irq_data, reserve);
    if (!ret)
        irqd_set_activated(irq_data);
    return ret;
}

/**
 * irq_domain_deactivate_irq - Call domain_ops->deactivate recursively to
 *                 deactivate interrupt
 * @irq_data: outermost irq_data associated with interrupt
 *
 * It calls domain_ops->deactivate to program interrupt controllers to disable
 * interrupt delivery.
 */
void irq_domain_deactivate_irq(struct irq_data *irq_data)
{
    if (irqd_is_activated(irq_data)) {
        __irq_domain_deactivate_irq(irq_data);
        irqd_clr_activated(irq_data);
    }
}

/**
 * irq_domain_translate_onecell() - Generic translate for direct one cell
 * bindings
 */
int irq_domain_translate_onecell(struct irq_domain *d,
                                 struct irq_fwspec *fwspec,
                                 unsigned long *out_hwirq,
                                 unsigned int *out_type)
{
    if (WARN_ON(fwspec->param_count < 1))
        return -EINVAL;
    *out_hwirq = fwspec->param[0];
    *out_type = IRQ_TYPE_NONE;
    return 0;
}
EXPORT_SYMBOL_GPL(irq_domain_translate_onecell);

/**
 * irq_domain_free_irqs_top - Clear handler and handler data, clear irqdata and free parent
 * @domain: Interrupt domain to match
 * @virq:   IRQ number to start with
 * @nr_irqs:    The number of irqs to free
 */
void irq_domain_free_irqs_top(struct irq_domain *domain,
                              unsigned int virq,
                              unsigned int nr_irqs)
{
    panic("%s: END!\n", __func__);
#if 0
    int i;

    for (i = 0; i < nr_irqs; i++) {
        irq_set_handler_data(virq + i, NULL);
        irq_set_handler(virq + i, NULL);
    }
    irq_domain_free_irqs_common(domain, virq, nr_irqs);
#endif
}

static struct irq_data *
irq_domain_insert_irq_data(struct irq_domain *domain, struct irq_data *child)
{
    struct irq_data *irq_data;

    irq_data = kzalloc_node(sizeof(*irq_data), GFP_KERNEL,
                            irq_data_get_node(child));
    if (irq_data) {
        child->parent_data = irq_data;
        irq_data->irq = child->irq;
        irq_data->common = child->common;
        irq_data->domain = domain;
    }

    return irq_data;
}

static void __irq_domain_free_hierarchy(struct irq_data *irq_data)
{
    struct irq_data *tmp;

    while (irq_data) {
        tmp = irq_data;
        irq_data = irq_data->parent_data;
        kfree(tmp);
    }
}

static void irq_domain_free_irq_data(unsigned int virq, unsigned int nr_irqs)
{
    struct irq_data *irq_data, *tmp;
    int i;

    for (i = 0; i < nr_irqs; i++) {
        irq_data = irq_get_irq_data(virq + i);
        tmp = irq_data->parent_data;
        irq_data->parent_data = NULL;
        irq_data->domain = NULL;

        __irq_domain_free_hierarchy(tmp);
    }
}

static int irq_domain_alloc_irq_data(struct irq_domain *domain,
                                     unsigned int virq, unsigned int nr_irqs)
{
    struct irq_data *irq_data;
    struct irq_domain *parent;
    int i;

    /* The outermost irq_data is embedded in struct irq_desc */
    for (i = 0; i < nr_irqs; i++) {
        irq_data = irq_get_irq_data(virq + i);
        irq_data->domain = domain;

        for (parent = domain->parent; parent; parent = parent->parent) {
            irq_data = irq_domain_insert_irq_data(parent, irq_data);
            if (!irq_data) {
                irq_domain_free_irq_data(virq, i + 1);
                return -ENOMEM;
            }
        }
    }

    return 0;
}

int irq_domain_alloc_irqs_hierarchy(struct irq_domain *domain,
                                    unsigned int irq_base,
                                    unsigned int nr_irqs, void *arg)
{
    if (!domain->ops->alloc) {
        pr_debug("domain->ops->alloc() is NULL\n");
        return -ENOSYS;
    }

    return domain->ops->alloc(domain, irq_base, nr_irqs, arg);
}

static int irq_domain_trim_hierarchy(unsigned int virq)
{
    struct irq_data *tail, *irqd, *irq_data;

    irq_data = irq_get_irq_data(virq);
    tail = NULL;

    /* The first entry must have a valid irqchip */
    if (!irq_data->chip || IS_ERR(irq_data->chip))
        return -EINVAL;

    /*
     * Validate that the irq_data chain is sane in the presence of
     * a hierarchy trimming marker.
     */
    for (irqd = irq_data->parent_data; irqd; irq_data = irqd, irqd = irqd->parent_data) {
        /* Can't have a valid irqchip after a trim marker */
        if (irqd->chip && tail)
            return -EINVAL;

        /* Can't have an empty irqchip before a trim marker */
        if (!irqd->chip && !tail)
            return -EINVAL;

        if (IS_ERR(irqd->chip)) {
            /* Only -ENOTCONN is a valid trim marker */
            if (PTR_ERR(irqd->chip) != -ENOTCONN)
                return -EINVAL;

            tail = irq_data;
        }
    }

    /* No trim marker, nothing to do */
    if (!tail)
        return 0;

    panic("%s: END!\n", __func__);
}

static void irq_domain_insert_irq(int virq)
{
    struct irq_data *data;

    for (data = irq_get_irq_data(virq); data; data = data->parent_data) {
        struct irq_domain *domain = data->domain;

        domain->mapcount++;
        irq_domain_set_mapping(domain, data->hwirq, data);

        /* If not already assigned, give the domain the chip's name */
        if (!domain->name && data->chip)
            domain->name = data->chip->name;
    }

    irq_clear_status_flags(virq, IRQ_NOREQUEST);
}

/**
 * __irq_domain_alloc_irqs - Allocate IRQs from domain
 * @domain: domain to allocate from
 * @irq_base:   allocate specified IRQ number if irq_base >= 0
 * @nr_irqs:    number of IRQs to allocate
 * @node:   NUMA node id for memory allocation
 * @arg:    domain specific argument
 * @realloc:    IRQ descriptors have already been allocated if true
 * @affinity:   Optional irq affinity mask for multiqueue devices
 *
 * Allocate IRQ numbers and initialized all data structures to support
 * hierarchy IRQ domains.
 * Parameter @realloc is mainly to support legacy IRQs.
 * Returns error code or allocated IRQ number
 *
 * The whole process to setup an IRQ has been split into two steps.
 * The first step, __irq_domain_alloc_irqs(), is to allocate IRQ
 * descriptor and required hardware resources. The second step,
 * irq_domain_activate_irq(), is to program the hardware with preallocated
 * resources. In this way, it's easier to rollback when failing to
 * allocate resources.
 */
int
__irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
                        unsigned int nr_irqs, int node, void *arg,
                        bool realloc, const struct irq_affinity_desc *affinity)
{
    int i, ret, virq;

    if (domain == NULL) {
        domain = irq_default_domain;
        if (WARN(!domain, "domain is NULL; cannot allocate IRQ\n"))
            return -EINVAL;
    }

    if (realloc && irq_base >= 0) {
        virq = irq_base;
    } else {
        virq = irq_domain_alloc_descs(irq_base, nr_irqs, 0, node, affinity);
        if (virq < 0) {
            pr_debug("cannot allocate IRQ(base %d, count %d)\n",
                     irq_base, nr_irqs);
            return virq;
        }
        printk("%s: virq(%d)\n", __func__, virq);
    }

    if (irq_domain_alloc_irq_data(domain, virq, nr_irqs)) {
        pr_debug("cannot allocate memory for IRQ%d\n", virq);
        ret = -ENOMEM;
        goto out_free_desc;
    }

    mutex_lock(&irq_domain_mutex);
    ret = irq_domain_alloc_irqs_hierarchy(domain, virq, nr_irqs, arg);
    if (ret < 0) {
        mutex_unlock(&irq_domain_mutex);
        goto out_free_irq_data;
    }

    for (i = 0; i < nr_irqs; i++) {
        ret = irq_domain_trim_hierarchy(virq + i);
        if (ret) {
            mutex_unlock(&irq_domain_mutex);
            goto out_free_irq_data;
        }
    }

    for (i = 0; i < nr_irqs; i++)
        irq_domain_insert_irq(virq + i);
    mutex_unlock(&irq_domain_mutex);

    return virq;

 out_free_irq_data:
    irq_domain_free_irq_data(virq, nr_irqs);
 out_free_desc:
    irq_free_descs(virq, nr_irqs);
    return ret;
}
EXPORT_SYMBOL_GPL(__irq_domain_alloc_irqs);
