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
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/radix-tree.h>
#include <linux/bitmap.h>
#include <linux/irqdomain.h>
#include <linux/sysfs.h>

#include "internals.h"

int nr_irqs = NR_IRQS;
EXPORT_SYMBOL_GPL(nr_irqs);

static DEFINE_MUTEX(sparse_irq_lock);
static DECLARE_BITMAP(allocated_irqs, IRQ_BITMAP_BITS);

static RADIX_TREE(irq_desc_tree, GFP_KERNEL);

static struct kobj_type irq_kobj_type = {
#if 0
    .release    = irq_kobj_release,
    .sysfs_ops  = &kobj_sysfs_ops,
    .default_groups = irq_groups,
#endif
};

struct irq_desc *irq_to_desc(unsigned int irq)
{
    return radix_tree_lookup(&irq_desc_tree, irq);
}

int handle_irq_desc(struct irq_desc *desc)
{
    if (!desc)
        return -EINVAL;

    generic_handle_irq_desc(desc);
    return 0;
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
    return handle_irq_desc(irq_resolve_mapping(domain, hwirq));
}
EXPORT_SYMBOL_GPL(generic_handle_domain_irq);

static int irq_expand_nr_irqs(unsigned int nr)
{
    if (nr > IRQ_BITMAP_BITS)
        return -ENOMEM;
    nr_irqs = nr;
    return 0;
}

static int alloc_masks(struct irq_desc *desc, int node)
{
    if (!zalloc_cpumask_var_node(&desc->irq_common_data.affinity,
                                 GFP_KERNEL, node))
        return -ENOMEM;

    return 0;
}

static void desc_smp_init(struct irq_desc *desc, int node,
                          const struct cpumask *affinity)
{
    if (!affinity)
        affinity = irq_default_affinity;
    cpumask_copy(desc->irq_common_data.affinity, affinity);
}

static void
desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
                  const struct cpumask *affinity, struct module *owner)
{
    int cpu;

    desc->irq_common_data.handler_data = NULL;
    desc->irq_common_data.msi_desc = NULL;

    desc->irq_data.common = &desc->irq_common_data;
    desc->irq_data.irq = irq;
    desc->irq_data.chip = &no_irq_chip;
    desc->irq_data.chip_data = NULL;
    irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
    irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
    irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
    desc->handle_irq = handle_bad_irq;
    desc->depth = 1;
    desc->irq_count = 0;
    desc->irqs_unhandled = 0;
    desc->tot_count = 0;
    desc->name = NULL;
    desc->owner = owner;
    for_each_possible_cpu(cpu)
        *per_cpu_ptr(desc->kstat_irqs, cpu) = 0;
    desc_smp_init(desc, node, affinity);
}

static struct irq_desc *
alloc_desc(int irq, int node, unsigned int flags,
           const struct cpumask *affinity,
           struct module *owner)
{
    struct irq_desc *desc;

    desc = kzalloc_node(sizeof(*desc), GFP_KERNEL, node);
    if (!desc)
        return NULL;
    /* allocate based on nr_cpu_ids */
    desc->kstat_irqs = alloc_percpu(unsigned int);
    if (!desc->kstat_irqs)
        goto err_desc;

    if (alloc_masks(desc, node))
        goto err_kstat;

    raw_spin_lock_init(&desc->lock);
    mutex_init(&desc->request_mutex);
#if 0
    init_waitqueue_head(&desc->wait_for_threads);
#endif

    desc_set_defaults(irq, desc, node, affinity, owner);
    irqd_set(&desc->irq_data, flags);
    kobject_init(&desc->kobj, &irq_kobj_type);

    return desc;

err_kstat:
    free_percpu(desc->kstat_irqs);
err_desc:
    kfree(desc);
    return NULL;
}

static void irq_insert_desc(unsigned int irq, struct irq_desc *desc)
{
    radix_tree_insert(&irq_desc_tree, irq, desc);
}

static void delete_irq_desc(unsigned int irq)
{
    radix_tree_delete(&irq_desc_tree, irq);
}

static void delayed_free_desc(struct rcu_head *rhp)
{
    struct irq_desc *desc = container_of(rhp, struct irq_desc, rcu);

    kobject_put(&desc->kobj);
}

static void free_desc(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

#if 0
    unregister_irq_proc(irq, desc);

    /*
     * sparse_irq_lock protects also show_interrupts() and
     * kstat_irq_usr(). Once we deleted the descriptor from the
     * sparse tree we can free it. Access in proc will fail to
     * lookup the descriptor.
     *
     * The sysfs entry must be serialized against a concurrent
     * irq_sysfs_init() as well.
     */
    irq_sysfs_del(desc);
#endif
    delete_irq_desc(irq);

    /*
     * We free the descriptor, masks and stat fields via RCU. That
     * allows demultiplex interrupts to do rcu based management of
     * the child interrupts.
     * This also allows us to use rcu in kstat_irqs_usr().
     */
    call_rcu(&desc->rcu, delayed_free_desc);
}

static int
alloc_descs(unsigned int start, unsigned int cnt, int node,
            const struct irq_affinity_desc *affinity,
            struct module *owner)
{
    struct irq_desc *desc;
    int i;

    /* Validate affinity mask(s) */
    if (affinity) {
        for (i = 0; i < cnt; i++) {
            if (cpumask_empty(&affinity[i].mask))
                return -EINVAL;
        }
    }

    for (i = 0; i < cnt; i++) {
        const struct cpumask *mask = NULL;
        unsigned int flags = 0;

        if (affinity) {
            if (affinity->is_managed) {
                flags = IRQD_AFFINITY_MANAGED | IRQD_MANAGED_SHUTDOWN;
            }
            mask = &affinity->mask;
            node = cpu_to_node(cpumask_first(mask));
            affinity++;
        }

        desc = alloc_desc(start + i, node, flags, mask, owner);
        if (!desc)
            goto err;
        irq_insert_desc(start + i, desc);
#if 0
        irq_sysfs_add(start + i, desc);
#endif
    }
    bitmap_set(allocated_irqs, start, cnt);
    return start;

 err:
    for (i--; i >= 0; i--)
        free_desc(start + i);
    return -ENOMEM;
}

/**
 * __irq_alloc_descs - allocate and initialize a range of irq descriptors
 * @irq:    Allocate for specific irq number if irq >= 0
 * @from:   Start the search from this irq number
 * @cnt:    Number of consecutive irqs to allocate.
 * @node:   Preferred node on which the irq descriptor should be allocated
 * @owner:  Owning module (can be NULL)
 * @affinity:   Optional pointer to an affinity mask array of size @cnt which
 *      hints where the irq descriptors should be allocated and which
 *      default affinities to use
 *
 * Returns the first irq number or error code
 */
int __ref
__irq_alloc_descs(int irq,
                  unsigned int from, unsigned int cnt, int node,
                  struct module *owner,
                  const struct irq_affinity_desc *affinity)
{
    int start, ret;

    if (!cnt)
        return -EINVAL;

    if (irq >= 0) {
        if (from > irq)
            return -EINVAL;
        from = irq;
    } else {
        /*
         * For interrupts which are freely allocated the
         * architecture can force a lower bound to the @from
         * argument. x86 uses this to exclude the GSI space.
         */
        from = arch_dynirq_lower_bound(from);
    }

    mutex_lock(&sparse_irq_lock);

    start = bitmap_find_next_zero_area(allocated_irqs, IRQ_BITMAP_BITS,
                                       from, cnt, 0);
    ret = -EEXIST;
    if (irq >=0 && start != irq)
        goto unlock;

    if (start + cnt > nr_irqs) {
        ret = irq_expand_nr_irqs(start + cnt);
        if (ret)
            goto unlock;
    }
    ret = alloc_descs(start, cnt, node, affinity, owner);
 unlock:
    mutex_unlock(&sparse_irq_lock);
    return ret;
}

/**
 * irq_free_descs - free irq descriptors
 * @from:   Start of descriptor range
 * @cnt:    Number of consecutive irqs to free
 */
void irq_free_descs(unsigned int from, unsigned int cnt)
{
    int i;

    if (from >= nr_irqs || (from + cnt) > nr_irqs)
        return;

    mutex_lock(&sparse_irq_lock);
    for (i = 0; i < cnt; i++)
        free_desc(from + i);

    bitmap_clear(allocated_irqs, from, cnt);
    mutex_unlock(&sparse_irq_lock);
}
EXPORT_SYMBOL_GPL(irq_free_descs);

int irq_set_percpu_devid_partition(unsigned int irq,
                                   const struct cpumask *affinity)
{
    struct irq_desc *desc = irq_to_desc(irq);

    if (!desc)
        return -EINVAL;

    if (desc->percpu_enabled)
        return -EINVAL;

    desc->percpu_enabled = kzalloc(sizeof(*desc->percpu_enabled), GFP_KERNEL);

    if (!desc->percpu_enabled)
        return -ENOMEM;

    if (affinity)
        desc->percpu_affinity = affinity;
    else
        desc->percpu_affinity = cpu_possible_mask;

    irq_set_percpu_devid_flags(irq);
    return 0;
}

int irq_set_percpu_devid(unsigned int irq)
{
    return irq_set_percpu_devid_partition(irq, NULL);
}

struct irq_desc *
__irq_get_desc_lock(unsigned int irq, unsigned long *flags,
                    bool bus, unsigned int check)
{
    struct irq_desc *desc = irq_to_desc(irq);

    if (desc) {
        if (check & _IRQ_DESC_CHECK) {
            if ((check & _IRQ_DESC_PERCPU) &&
                !irq_settings_is_per_cpu_devid(desc))
                return NULL;

            if (!(check & _IRQ_DESC_PERCPU) &&
                irq_settings_is_per_cpu_devid(desc))
                return NULL;
        }

        if (bus)
            chip_bus_lock(desc);
        raw_spin_lock_irqsave(&desc->lock, *flags);
    }
    return desc;
}

void __irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags, bool bus)
    __releases(&desc->lock)
{
    raw_spin_unlock_irqrestore(&desc->lock, flags);
    if (bus)
        chip_bus_sync_unlock(desc);
}
