// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for working with the Flattened Device Tree data format
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/libfdt.h>
#include <linux/cache.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#include <asm/page.h>

void *initial_boot_params __ro_after_init;

bool __init early_init_dt_verify(void *params)
{
    if (!params)
        return false;

    /* check device tree validity */
    if (fdt_check_header(params))
        return false;

    /* Setup flat device-tree pointer */
    initial_boot_params = params;
    return true;
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob,
 * return the property ptr
 *
 * This function can be used within scan_flattened_dt callback to get
 * access to properties
 */
const void *__init
of_get_flat_dt_prop(unsigned long node, const char *name, int *size)
{
    return fdt_getprop(initial_boot_params, node, name, size);
}

int __init
early_init_dt_scan_chosen(unsigned long node, const char *uname,
                          int depth, void *data)
{
    int l;
    const char *p;

    if (depth != 1 || !data ||
        (strcmp(uname, "chosen") != 0 && strcmp(uname, "chosen@0") != 0))
        return 0;

    /* Retrieve command line */
    p = of_get_flat_dt_prop(node, "bootargs", &l);
    if (p != NULL && l > 0)
        strlcpy(data, p, min(l, COMMAND_LINE_SIZE));

    /* No arguments from boot loader, use kernel's  cmdl*/
    if (!((char *)data)[0])
        strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);

    /* break now */
    return 1;
}

/**
 * of_scan_flat_dt - scan flattened tree blob and call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan the flattened device-tree, it is
 * used to extract the memory information at boot before we can
 * unflatten the tree
 */
int __init
of_scan_flat_dt(int (*it)(unsigned long node, const char *uname,
                          int depth, void *data),
                void *data)
{
    const char *pathp;
    int offset, rc = 0, depth = -1;
    const void *blob = initial_boot_params;

    if (!blob)
        return 0;

    for (offset = fdt_next_node(blob, -1, &depth);
         offset >= 0 && depth >= 0 && !rc;
         offset = fdt_next_node(blob, offset, &depth)) {

        pathp = fdt_get_name(blob, offset, NULL);
        rc = it(offset, pathp, depth, data);
    }
    return rc;
}

void __init early_init_dt_scan_nodes(void)
{
    int rc = 0;

    /* Retrieve various information from the /chosen node */
    rc = of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);
    if (!rc)
        panic("No chosen node found, continuing without\n");
        //pr_warn("No chosen node found, continuing without\n");

    /* Initialize {size,address}-cells info */
    //of_scan_flat_dt(early_init_dt_scan_root, NULL);

    /* Setup memory, calling early_init_dt_add_memory_arch */
    //of_scan_flat_dt(early_init_dt_scan_memory, NULL);
}

bool __init early_init_dt_scan(void *params)
{
    bool status;

    status = early_init_dt_verify(params);
    if (!status)
        return false;

    early_init_dt_scan_nodes();
    return true;
}

/**
 * unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
void __init unflatten_device_tree(void)
{
#if 0
    __unflatten_device_tree(initial_boot_params, NULL, &of_root,
                            early_init_dt_alloc_memory_arch, false);

    /* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
    of_alias_scan(early_init_dt_alloc_memory_arch);

    unittest_unflatten_overlay_base();
#endif
}
