// SPDX-License-Identifier: GPL-2.0+
/*
 *    Copyright (C) 2006 Benjamin Herrenschmidt, IBM Corp.
 *           <benh@kernel.crashing.org>
 *    and        Arnd Bergmann, IBM Corp.
 *    Merged from powerpc/kernel/of_platform.c and
 *    sparc{,64}/kernel/of_device.c by Stephen Rothwell
 */

#define pr_fmt(fmt) "OF: " fmt

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/device.h>
#if 0
#include <linux/amba/bus.h>
#include <linux/dma-mapping.h>
#endif
#include <linux/slab.h>
#if 0
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#endif
#include <linux/of.h>
#include <linux/of_platform.h>

const struct of_device_id of_default_bus_match_table[] = {
    { .compatible = "simple-bus", },
    { .compatible = "simple-mfd", },
    { .compatible = "isa", },
    {} /* Empty terminated list */
};

/**
 * of_platform_populate() - Populate platform_devices from device tree data
 * @root: parent of the first level to probe or NULL for the root of the tree
 * @matches: match table, NULL to use the default
 * @lookup: auxdata table for matching id and platform_data with device nodes
 * @parent: parent to hook devices from, NULL for toplevel
 *
 * Similar to of_platform_bus_probe(), this function walks the device tree
 * and creates devices from nodes.  It differs in that it follows the modern
 * convention of requiring all device nodes to have a 'compatible' property,
 * and it is suitable for creating devices which are children of the root
 * node (of_platform_bus_probe will only create children of the root which
 * are selected by the @matches argument).
 *
 * New board support should be using this function instead of
 * of_platform_bus_probe().
 *
 * Return: 0 on success, < 0 on failure.
 */
int of_platform_populate(struct device_node *root,
                         const struct of_device_id *matches,
                         const struct of_dev_auxdata *lookup,
                         struct device *parent)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(of_platform_populate);

int of_platform_default_populate(struct device_node *root,
                                 const struct of_dev_auxdata *lookup,
                                 struct device *parent)
{
    return of_platform_populate(root, of_default_bus_match_table,
                                lookup, parent);
}
EXPORT_SYMBOL_GPL(of_platform_default_populate);

static int __init of_platform_default_populate_init(void)
{
#if 0
    struct device_node *node;

    device_links_supplier_sync_state_pause();
#endif

    if (!of_have_populated_dt())
        return -ENODEV;

#if 0
    /*
     * Handle certain compatibles explicitly, since we don't want to create
     * platform_devices for every node in /reserved-memory with a
     * "compatible",
     */
    for_each_matching_node(node, reserved_mem_matches)
        of_platform_device_create(node, NULL, NULL);

    node = of_find_node_by_path("/firmware");
    if (node) {
        of_platform_populate(node, NULL, NULL, NULL);
        of_node_put(node);
    }

    node = of_get_compatible_child(of_chosen, "simple-framebuffer");
    of_platform_device_create(node, NULL, NULL);
    of_node_put(node);
#endif

    /* Populate everything else. */
    of_platform_default_populate(NULL, NULL, NULL);

    panic("%s: END!\n", __func__);
    return 0;
}
arch_initcall_sync(of_platform_default_populate_init);
