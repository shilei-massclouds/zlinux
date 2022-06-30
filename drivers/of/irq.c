// SPDX-License-Identifier: GPL-2.0+
/*
 *  Derived from arch/i386/kernel/irq.c
 *    Copyright (C) 1992 Linus Torvalds
 *  Adapted from arch/i386 by Gary Thomas
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *  Updated and modified by Cort Dougan <cort@fsmlabs.com>
 *    Copyright (C) 1996-2001 Cort Dougan
 *  Adapted for Power Macintosh by Paul Mackerras
 *    Copyright (C) 1996 Paul Mackerras (paulus@cs.anu.edu.au)
 *
 * This file contains the code used to make IRQ descriptions in the
 * device tree to actual irq numbers on an interrupt controller
 * driver.
 */

#define pr_fmt(fmt) "OF: " fmt

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/string.h>
#include <linux/slab.h>

struct of_intc_desc {
    struct list_head    list;
    of_irq_init_cb_t    irq_init_cb;
    struct device_node  *dev;
    struct device_node  *interrupt_parent;
};

/**
 * of_irq_find_parent - Given a device node, find its interrupt parent node
 * @child: pointer to device node
 *
 * Return: A pointer to the interrupt parent node, or NULL if the interrupt
 * parent could not be determined.
 */
struct device_node *of_irq_find_parent(struct device_node *child)
{
    struct device_node *p;
    phandle parent;

    if (!of_node_get(child))
        return NULL;

    do {
        if (of_property_read_u32(child, "interrupt-parent", &parent)) {
            p = of_get_parent(child);
        } else  {
            p = of_find_node_by_phandle(parent);
        }
        of_node_put(child);
        child = p;
    } while (p && of_get_property(p, "#interrupt-cells", NULL) == NULL);

    return p;
}
EXPORT_SYMBOL_GPL(of_irq_find_parent);

/*
 * These interrupt controllers abuse interrupt-map for unspeakable
 * reasons and rely on the core code to *ignore* it (the drivers do
 * their own parsing of the property).
 *
 * If you think of adding to the list for something *new*, think
 * again. There is a high chance that you will be sent back to the
 * drawing board.
 */
static const char * const of_irq_imap_abusers[] = {
    "CBEA,platform-spider-pic",
    "sti,platform-spider-pic",
    "realtek,rtl-intc",
    "fsl,ls1021a-extirq",
    "fsl,ls1043a-extirq",
    "fsl,ls1088a-extirq",
    "renesas,rza1-irqc",
    NULL,
};

/**
 * of_irq_parse_raw - Low level interrupt tree parsing
 * @addr:   address specifier (start of "reg" property of the device) in be32 format
 * @out_irq:    structure of_phandle_args updated by this function
 *
 * This function is a low-level interrupt tree walking function. It
 * can be used to do a partial walk with synthetized reg and interrupts
 * properties, for example when resolving PCI interrupts when no device
 * node exist for the parent. It takes an interrupt specifier structure as
 * input, walks the tree looking for any interrupt-map properties, translates
 * the specifier for each map, and then returns the translated map.
 *
 * Return: 0 on success and a negative number on error
 */
int of_irq_parse_raw(const __be32 *addr, struct of_phandle_args *out_irq)
{
    struct device_node *ipar, *tnode, *old = NULL, *newpar = NULL;
    __be32 initial_match_array[MAX_PHANDLE_ARGS];
    const __be32 *match_array = initial_match_array;
    const __be32 *tmp, *imap, *imask, dummy_imask[] =
        { [0 ... MAX_PHANDLE_ARGS] = cpu_to_be32(~0) };
    u32 intsize = 1, addrsize, newintsize = 0, newaddrsize = 0;
    int imaplen, match, i, rc = -EINVAL;

    ipar = of_node_get(out_irq->np);

    /* First get the #interrupt-cells property of the current cursor
     * that tells us how to interpret the passed-in intspec. If there
     * is none, we are nice and just walk up the tree
     */
    do {
        if (!of_property_read_u32(ipar, "#interrupt-cells", &intsize))
            break;
        tnode = ipar;
        ipar = of_irq_find_parent(ipar);
        of_node_put(tnode);
    } while (ipar);
    if (ipar == NULL) {
        pr_debug(" -> no parent found !\n");
        goto fail;
    }

    pr_debug("of_irq_parse_raw: ipar=%pOF, size=%d\n", ipar, intsize);

    if (out_irq->args_count != intsize)
        goto fail;

    /* Look for this #address-cells. We have to implement the old linux
     * trick of looking for the parent here as some device-trees rely on it
     */
    old = of_node_get(ipar);
    do {
        tmp = of_get_property(old, "#address-cells", NULL);
        tnode = of_get_parent(old);
        of_node_put(old);
        old = tnode;
    } while (old && tmp == NULL);
    of_node_put(old);
    old = NULL;
    addrsize = (tmp == NULL) ? 2 : be32_to_cpu(*tmp);

    pr_debug(" -> addrsize=%d\n", addrsize);

    /* Range check so that the temporary buffer doesn't overflow */
    if (WARN_ON(addrsize + intsize > MAX_PHANDLE_ARGS)) {
        rc = -EFAULT;
        goto fail;
    }

    /* Precalculate the match array - this simplifies match loop */
    for (i = 0; i < addrsize; i++)
        initial_match_array[i] = addr ? addr[i] : 0;
    for (i = 0; i < intsize; i++)
        initial_match_array[addrsize + i] = cpu_to_be32(out_irq->args[i]);

    /* Now start the actual "proper" walk of the interrupt tree */
    while (ipar != NULL) {
        /*
         * Now check if cursor is an interrupt-controller and
         * if it is then we are done, unless there is an
         * interrupt-map which takes precedence except on one
         * of these broken platforms that want to parse
         * interrupt-map themselves for $reason.
         */
        bool intc = of_property_read_bool(ipar, "interrupt-controller");

        imap = of_get_property(ipar, "interrupt-map", &imaplen);
        if (intc &&
            (!imap || of_device_compatible_match(ipar, of_irq_imap_abusers))) {
            pr_debug(" -> got it !\n");
            return 0;
        }

        panic("%s: ipar(%pOF) intc(%d)!\n", __func__, ipar, intc);
    }

    panic("%s: END!\n", __func__);

    rc = -ENOENT; /* No interrupt-map found */

 fail:
    of_node_put(ipar);
    of_node_put(newpar);

    return rc;
}

/**
 * of_irq_parse_one - Resolve an interrupt for a device
 * @device: the device whose interrupt is to be resolved
 * @index: index of the interrupt to resolve
 * @out_irq: structure of_phandle_args filled by this function
 *
 * This function resolves an interrupt for a node by walking the interrupt tree,
 * finding which interrupt controller node it is attached to, and returning the
 * interrupt specifier that can be used to retrieve a Linux IRQ number.
 */
int of_irq_parse_one(struct device_node *device, int index,
                     struct of_phandle_args *out_irq)
{
    struct device_node *p;
    const __be32 *addr;
    u32 intsize;
    int i, res;

    pr_info("of_irq_parse_one: dev=%pOF, index=%d\n", device, index);

    /* Get the reg property (if any) */
    addr = of_get_property(device, "reg", NULL);

    /* Try the new-style interrupts-extended first */
    res = of_parse_phandle_with_args(device, "interrupts-extended",
                                     "#interrupt-cells", index, out_irq);
    if (!res)
        return of_irq_parse_raw(addr, out_irq);

    /* Look for the interrupt parent. */
    p = of_irq_find_parent(device);
    if (p == NULL)
        return -EINVAL;

    /* Get size of interrupt specifier */
    if (of_property_read_u32(p, "#interrupt-cells", &intsize)) {
        res = -EINVAL;
        goto out;
    }

    pr_debug(" parent=%pOF, intsize=%d\n", p, intsize);

    /* Copy intspec into irq structure */
    out_irq->np = p;
    out_irq->args_count = intsize;
    for (i = 0; i < intsize; i++) {
        res = of_property_read_u32_index(device, "interrupts",
                                         (index * intsize) + i,
                                         out_irq->args + i);
        if (res)
            goto out;
    }

    pr_debug(" intspec=%d\n", *out_irq->args);

    /* Check if there are any interrupt-map translations to process */
    res = of_irq_parse_raw(addr, out_irq);
 out:
    of_node_put(p);
    return res;
}

/**
 * of_irq_count - Count the number of IRQs a node uses
 * @dev: pointer to device tree node
 */
int of_irq_count(struct device_node *dev)
{
    struct of_phandle_args irq;
    int nr = 0;

    while (of_irq_parse_one(dev, nr, &irq) == 0)
        nr++;

    return nr;
}

/**
 * of_irq_get - Decode a node's IRQ and return it as a Linux IRQ number
 * @dev: pointer to device tree node
 * @index: zero-based index of the IRQ
 *
 * Return: Linux IRQ number on success, or 0 on the IRQ mapping failure, or
 * -EPROBE_DEFER if the IRQ domain is not yet created, or error code in case
 * of any other failure.
 */
int of_irq_get(struct device_node *dev, int index)
{
    int rc;
    struct of_phandle_args oirq;
    struct irq_domain *domain;

    rc = of_irq_parse_one(dev, index, &oirq);
    if (rc)
        return rc;

    domain = irq_find_host(oirq.np);
    if (!domain)
        return -EPROBE_DEFER;

    panic("%s: END!\n", __func__);
    //return irq_create_of_mapping(&oirq);
}
EXPORT_SYMBOL_GPL(of_irq_get);

/**
 * of_irq_to_resource - Decode a node's IRQ and return it as a resource
 * @dev: pointer to device tree node
 * @index: zero-based index of the irq
 * @r: pointer to resource structure to return result into.
 */
int of_irq_to_resource(struct device_node *dev, int index, struct resource *r)
{
    int irq = of_irq_get(dev, index);

    if (irq < 0)
        return irq;

    /* Only dereference the resource if both the
     * resource and the irq are valid. */
    if (r && irq) {
        const char *name = NULL;

        memset(r, 0, sizeof(*r));
        /*
         * Get optional "interrupt-names" property to add a name
         * to the resource.
         */
        of_property_read_string_index(dev, "interrupt-names", index, &name);

        r->start = r->end = irq;
        r->flags = IORESOURCE_IRQ | irqd_get_trigger_type(irq_get_irq_data(irq));
        r->name = name ? name : of_node_full_name(dev);
    }

    return irq;
}
EXPORT_SYMBOL_GPL(of_irq_to_resource);

/**
 * of_irq_to_resource_table - Fill in resource table with node's IRQ info
 * @dev: pointer to device tree node
 * @res: array of resources to fill in
 * @nr_irqs: the number of IRQs (and upper bound for num of @res elements)
 *
 * Return: The size of the filled in table (up to @nr_irqs).
 */
int of_irq_to_resource_table(struct device_node *dev, struct resource *res,
                             int nr_irqs)
{
    int i;

    for (i = 0; i < nr_irqs; i++, res++)
        if (of_irq_to_resource(dev, i, res) <= 0)
            break;

    return i;
}
EXPORT_SYMBOL_GPL(of_irq_to_resource_table);

/**
 * of_irq_init - Scan and init matching interrupt controllers in DT
 * @matches: 0 terminated array of nodes to match and init function to call
 *
 * This function scans the device tree for matching interrupt controller nodes,
 * and calls their initialization functions in order with parents first.
 */
void __init of_irq_init(const struct of_device_id *matches)
{
    const struct of_device_id *match;
    struct device_node *np, *parent = NULL;
    struct of_intc_desc *desc, *temp_desc;
    struct list_head intc_desc_list, intc_parent_list;

    INIT_LIST_HEAD(&intc_desc_list);
    INIT_LIST_HEAD(&intc_parent_list);

    for_each_matching_node_and_match(np, matches, &match) {
        if (!of_property_read_bool(np, "interrupt-controller") ||
            !of_device_is_available(np))
            continue;

        if (WARN(!match->data, "of_irq_init: no init function for %s\n",
                 match->compatible))
            continue;

        /*
         * Here, we allocate and populate an of_intc_desc with the node
         * pointer, interrupt-parent device_node etc.
         */
        desc = kzalloc(sizeof(*desc), GFP_KERNEL);
        if (!desc) {
            of_node_put(np);
            goto err;
        }

        desc->irq_init_cb = match->data;
        desc->dev = of_node_get(np);
        desc->interrupt_parent = of_irq_find_parent(np);
        if (desc->interrupt_parent == np)
            desc->interrupt_parent = NULL;
        list_add_tail(&desc->list, &intc_desc_list);
    }

    /*
     * The root irq controller is the one without an interrupt-parent.
     * That one goes first, followed by the controllers that reference it,
     * followed by the ones that reference the 2nd level controllers, etc.
     */
    while (!list_empty(&intc_desc_list)) {
        /*
         * Process all controllers with the current 'parent'.
         * First pass will be looking for NULL as the parent.
         * The assumption is that NULL parent means a root controller.
         */
        list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
            int ret;

            if (desc->interrupt_parent != parent)
                continue;

            list_del(&desc->list);

            of_node_set_flag(desc->dev, OF_POPULATED);

            pr_info("of_irq_init: init %pOF (%p), parent %p\n",
                     desc->dev, desc->dev, desc->interrupt_parent);

            ret = desc->irq_init_cb(desc->dev, desc->interrupt_parent);
            if (ret) {
                of_node_clear_flag(desc->dev, OF_POPULATED);
                kfree(desc);
                continue;
            }

            /*
             * This one is now set up; add it to the parent list so
             * its children can get processed in a subsequent pass.
             */
            list_add_tail(&desc->list, &intc_parent_list);
        }

        /* Get the next pending parent that might have children */
        desc = list_first_entry_or_null(&intc_parent_list, typeof(*desc), list);
        if (!desc) {
            pr_err("of_irq_init: children remain, but no parents\n");
            break;
        }
        list_del(&desc->list);
        parent = desc->dev;
        kfree(desc);
    }

    list_for_each_entry_safe(desc, temp_desc, &intc_parent_list, list) {
        list_del(&desc->list);
        kfree(desc);
    }

 err:
    list_for_each_entry_safe(desc, temp_desc, &intc_desc_list, list) {
        list_del(&desc->list);
        of_node_put(desc->dev);
        kfree(desc);
    }
}
