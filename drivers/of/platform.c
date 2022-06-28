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
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/ioport.h>

const struct of_device_id of_default_bus_match_table[] = {
    { .compatible = "simple-bus", },
    { .compatible = "simple-mfd", },
    { .compatible = "isa", },
    {} /* Empty terminated list */
};

static const struct of_device_id of_skipped_node_table[] = {
    { .compatible = "operating-points-v2", },
    {} /* Empty terminated list */
};

/*
 * of_dev_lookup() - Given a device node, lookup the preferred Linux name
 */
static const struct of_dev_auxdata *
of_dev_lookup(const struct of_dev_auxdata *lookup, struct device_node *np)
{
    const struct of_dev_auxdata *auxdata;
    //struct resource res;
    int compatible = 0;

    if (!lookup)
        return NULL;

    panic("%s: NO implementation!\n", __func__);
}

/**
 * of_device_make_bus_id - Use the device node data to assign a unique name
 * @dev: pointer to device structure that is linked to a device tree node
 *
 * This routine will first try using the translated bus address to
 * derive a unique name. If it cannot, then it will prepend names from
 * parent nodes until a unique name can be derived.
 */
static void of_device_make_bus_id(struct device *dev)
{
    struct device_node *node = dev->of_node;
    const __be32 *reg;
    u64 addr;
    u32 mask;

    /* Construct the name, using parent nodes if necessary to ensure uniqueness */
    while (node->parent) {
        /*
         * If the address can be translated, then that is as much
         * uniqueness as we need. Make it the first component and return
         */
        reg = of_get_property(node, "reg", NULL);
        if (reg && (addr = of_translate_address(node, reg)) != OF_BAD_ADDR) {
            if (!of_property_read_u32(node, "mask", &mask))
                dev_set_name(dev, dev_name(dev) ?
                             "%llx.%x.%pOFn:%s" : "%llx.%x.%pOFn",
                             addr, ffs(mask) - 1, node, dev_name(dev));

            else
                dev_set_name(dev, dev_name(dev) ?
                             "%llx.%pOFn:%s" : "%llx.%pOFn",
                             addr, node, dev_name(dev));
            return;
        }

        panic("%s: node(%pOF) NO implementation!\n", __func__, node);
    }

    panic("%s: END!\n", __func__);
}

/**
 * of_device_alloc - Allocate and initialize an of_device
 * @np: device node to assign to device
 * @bus_id: Name to assign to the device.  May be null to use default name.
 * @parent: Parent device.
 */
struct platform_device *
of_device_alloc(struct device_node *np,
                const char *bus_id,
                struct device *parent)
{
    struct platform_device *dev;
    int rc, i, num_reg = 0, num_irq;
    struct resource *res, temp_res;

    dev = platform_device_alloc("", PLATFORM_DEVID_NONE);
    if (!dev)
        return NULL;

    /* count the io and irq resources */
    while (of_address_to_resource(np, num_reg, &temp_res) == 0)
        num_reg++;
    num_irq = of_irq_count(np);

    /* Populate the resource table */
    if (num_irq || num_reg) {
        res = kcalloc(num_irq + num_reg, sizeof(*res), GFP_KERNEL);
        if (!res) {
            platform_device_put(dev);
            return NULL;
        }

        dev->num_resources = num_reg + num_irq;
        dev->resource = res;
        for (i = 0; i < num_reg; i++, res++) {
            rc = of_address_to_resource(np, i, res);
            WARN_ON(rc);
        }
        if (of_irq_to_resource_table(np, res, num_irq) != num_irq)
            pr_err("not all legacy IRQ resources mapped for %pOFn\n", np);
    }

    dev->dev.of_node = of_node_get(np);
    dev->dev.fwnode = &np->fwnode;
    dev->dev.parent = parent ? : &platform_bus;

    if (bus_id)
        dev_set_name(&dev->dev, "%s", bus_id);
    else
        of_device_make_bus_id(&dev->dev);

    pr_info("%s: num_reg(%d) num_irq(%d) END!\n", __func__, num_reg, num_irq);
    return dev;
}

/**
 * of_platform_device_create_pdata - Alloc, initialize and register an of_device
 * @np: pointer to node to create device for
 * @bus_id: name to assign device
 * @platform_data: pointer to populate platform_data pointer with
 * @parent: Linux device model parent device.
 *
 * Return: Pointer to created platform device, or NULL if a device was not
 * registered.  Unavailable devices will not get registered.
 */
static struct platform_device *
of_platform_device_create_pdata(struct device_node *np,
                                const char *bus_id,
                                void *platform_data,
                                struct device *parent)
{
    struct platform_device *dev;

    if (!of_device_is_available(np) ||
        of_node_test_and_set_flag(np, OF_POPULATED))
        return NULL;

    dev = of_device_alloc(np, bus_id, parent);
    if (!dev)
        goto err_clear_flag;

#if 0
    dev->dev.coherent_dma_mask = DMA_BIT_MASK(32);
    if (!dev->dev.dma_mask)
        dev->dev.dma_mask = &dev->dev.coherent_dma_mask;
#endif
    dev->dev.bus = &platform_bus_type;
    dev->dev.platform_data = platform_data;
#if 0
    of_msi_configure(&dev->dev, dev->dev.of_node);
#endif

    if (of_device_add(dev) != 0) {
        platform_device_put(dev);
        goto err_clear_flag;
    }

    return dev;

err_clear_flag:
    of_node_clear_flag(np, OF_POPULATED);
    return NULL;
}

/**
 * of_platform_bus_create() - Create a device for a node and its children.
 * @bus: device node of the bus to instantiate
 * @matches: match table for bus nodes
 * @lookup: auxdata table for matching id and platform_data with device nodes
 * @parent: parent for new device, or NULL for top level.
 * @strict: require compatible property
 *
 * Creates a platform_device for the provided device_node, and optionally
 * recursively create devices for all the child nodes.
 */
static int of_platform_bus_create(struct device_node *bus,
                                  const struct of_device_id *matches,
                                  const struct of_dev_auxdata *lookup,
                                  struct device *parent, bool strict)
{
    int rc = 0;
    struct device_node *child;
    const char *bus_id = NULL;
    void *platform_data = NULL;
    struct platform_device *dev;
    const struct of_dev_auxdata *auxdata;

    /* Make sure it has a compatible property */
    if (strict && (!of_get_property(bus, "compatible", NULL))) {
        pr_debug("%s() - skipping %pOF, no compatible prop\n",
                 __func__, bus);
        return 0;
    }

    /* Skip nodes for which we don't want to create devices */
    if (unlikely(of_match_node(of_skipped_node_table, bus))) {
        pr_debug("%s() - skipping %pOF node\n", __func__, bus);
        return 0;
    }

    if (of_node_check_flag(bus, OF_POPULATED_BUS)) {
        pr_debug("%s() - skipping %pOF, already populated\n",
                 __func__, bus);
        return 0;
    }

    auxdata = of_dev_lookup(lookup, bus);
    if (auxdata) {
        bus_id = auxdata->name;
        platform_data = auxdata->platform_data;
    }

    dev = of_platform_device_create_pdata(bus, bus_id, platform_data, parent);
    if (!dev || !of_match_node(matches, bus))
        return 0;

    panic("%s: name(%s) END!\n", __func__, bus->name);
}

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
    struct device_node *child;
    int rc = 0;

    root = root ? of_node_get(root) : of_find_node_by_path("/");
    if (!root)
        return -EINVAL;

    pr_info("%s()\n", __func__);
    pr_info(" starting at: %pOF\n", root);

    //device_links_supplier_sync_state_pause();
    for_each_child_of_node(root, child) {
        rc = of_platform_bus_create(child, matches, lookup, parent, true);
        if (rc) {
            of_node_put(child);
            break;
        }
    }
    //device_links_supplier_sync_state_resume();

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

int __init platform_bus_init(void)
{
    int error;

    error = device_register(&platform_bus);
    if (error) {
        put_device(&platform_bus);
        return error;
    }
    error = bus_register(&platform_bus_type);
    if (error)
        device_unregister(&platform_bus);
    return error;
}
