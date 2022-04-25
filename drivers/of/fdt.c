// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for working with the Flattened Device Tree data format
 */

//#include <linux/crc32.h>
#include <linux/kernel.h>
//#include <linux/initrd.h>
#include <linux/memblock.h>
//#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
//#include <linux/of_reserved_mem.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
//#include <linux/slab.h>
#include <linux/libfdt.h>
//#include <linux/debugfs.h>
#include <linux/serial_core.h>
/*
#include <linux/sysfs.h>
#include <linux/random.h>
*/

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#include <asm/page.h>

#include "of_private.h"

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;
int __initdata dt_root_size_cells;

void *initial_boot_params __ro_after_init;

static bool
of_fdt_device_is_available(const void *blob, unsigned long node)
{
    const char *status = fdt_getprop(blob, node, "status", NULL);

    if (!status)
        return true;

    if (!strcmp(status, "ok") || !strcmp(status, "okay"))
        return true;

    return false;
}

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

/**
 * early_init_dt_scan_root - fetch the top level address and size cells
 */
int __init
early_init_dt_scan_root(unsigned long node, const char *uname,
                        int depth, void *data)
{
    const __be32 *prop;

    if (depth != 0)
        return 0;

    dt_root_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
    dt_root_addr_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;

    prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
    if (prop)
        dt_root_size_cells = be32_to_cpup(prop);
    pr_debug("dt_root_size_cells = %x\n", dt_root_size_cells);

    prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
    if (prop)
        dt_root_addr_cells = be32_to_cpup(prop);
    pr_debug("dt_root_addr_cells = %x\n", dt_root_addr_cells);

    /* break now */
    return 1;
}

u64 __init dt_mem_next_cell(int s, const __be32 **cellp)
{
    const __be32 *p = *cellp;

    *cellp = p + s;
    return of_read_number(p, s);
}

#ifndef MIN_MEMBLOCK_ADDR
#define MIN_MEMBLOCK_ADDR   __pa(PAGE_OFFSET)
#endif
#ifndef MAX_MEMBLOCK_ADDR
#define MAX_MEMBLOCK_ADDR   ((phys_addr_t)~0)
#endif

void __init __weak early_init_dt_add_memory_arch(u64 base, u64 size)
{
    const u64 phys_offset = MIN_MEMBLOCK_ADDR;

    if (size < PAGE_SIZE - (base & ~PAGE_MASK)) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
                base, base + size);
        return;
    }

    if (!PAGE_ALIGNED(base)) {
        size -= PAGE_SIZE - (base & ~PAGE_MASK);
        base = PAGE_ALIGN(base);
    }
    size &= PAGE_MASK;

    if (base > MAX_MEMBLOCK_ADDR) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
                base, base + size);
        return;
    }

    if (base + size - 1 > MAX_MEMBLOCK_ADDR) {
        pr_warn("Ignoring memory range 0x%llx - 0x%llx\n",
                ((u64)MAX_MEMBLOCK_ADDR) + 1, base + size);
        size = MAX_MEMBLOCK_ADDR - base + 1;
    }

    if (base + size < phys_offset) {
        pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
                base, base + size);
        return;
    }
    if (base < phys_offset) {
        pr_warn("Ignoring memory range 0x%llx - 0x%llx\n",
                base, phys_offset);
        size -= phys_offset - base;
        base = phys_offset;
    }
    memblock_add(base, size);
}

/**
 * early_init_dt_scan_memory - Look for and parse memory nodes
 */
int __init
early_init_dt_scan_memory(unsigned long node, const char *uname,
                          int depth, void *data)
{
    int l;
    bool hotpluggable;
    const __be32 *reg, *endp;
    const char *type = of_get_flat_dt_prop(node, "device_type", NULL);

    /* We are scanning "memory" nodes only */
    if (type == NULL || strcmp(type, "memory") != 0)
        return 0;

    reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);
    if (reg == NULL)
        reg = of_get_flat_dt_prop(node, "reg", &l);
    if (reg == NULL)
        return 0;

    endp = reg + (l / sizeof(__be32));
    hotpluggable = of_get_flat_dt_prop(node, "hotpluggable", NULL);

    pr_debug("memory scan node %s, reg size %d,\n", uname, l);

    while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
        u64 base, size;

        base = dt_mem_next_cell(dt_root_addr_cells, &reg);
        size = dt_mem_next_cell(dt_root_size_cells, &reg);

        if (size == 0)
            continue;
        pr_debug(" - %llx ,  %llx\n", (unsigned long long)base,
                 (unsigned long long)size);

        early_init_dt_add_memory_arch(base, size);

        if (!hotpluggable)
            continue;

#if 0
        if (early_init_dt_mark_hotplug_memory_arch(base, size))
            pr_warn("failed to mark hotplug range 0x%llx - 0x%llx\n",
                    base, base + size);
#endif
    }

    return 0;
}

void __init early_init_dt_scan_nodes(void)
{
    int rc = 0;

    /* Retrieve various information from the /chosen node */
    rc = of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);
    if (!rc)
        pr_warn("No chosen node found, continuing without\n");

    /* Initialize {size,address}-cells info */
    of_scan_flat_dt(early_init_dt_scan_root, NULL);

    /* Setup memory, calling early_init_dt_add_memory_arch */
    of_scan_flat_dt(early_init_dt_scan_memory, NULL);
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

int __init __weak
early_init_dt_reserve_memory_arch(phys_addr_t base,
                                  phys_addr_t size, bool nomap)
{
    if (nomap)
        return memblock_remove(base, size);
    return memblock_reserve(base, size);
}

/**
 * __reserved_mem_check_root() -
 * check if #size-cells, #address-cells provided in /reserved-memory
 * matches the values supported by the current implementation,
 * also check if ranges property has been provided
 */
static int __init __reserved_mem_check_root(unsigned long node)
{
    const __be32 *prop;

    prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
    if (!prop || be32_to_cpup(prop) != dt_root_size_cells)
        return -EINVAL;

    prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
    if (!prop || be32_to_cpup(prop) != dt_root_addr_cells)
        return -EINVAL;

    prop = of_get_flat_dt_prop(node, "ranges", NULL);
    if (!prop)
        return -EINVAL;
    return 0;
}

/**
 * fdt_scan_reserved_mem() - scan a single FDT node for reserved memory
 */
static int __init
__fdt_scan_reserved_mem(unsigned long node, const char *uname,
                        int depth, void *data)
{
    int err;
    static int found;

    if (!found && depth == 1 && strcmp(uname, "reserved-memory") == 0) {
        if (__reserved_mem_check_root(node) != 0) {
            pr_err("Reserved memory: unsupported node format, ignoring\n");
            /* break scan */
            return 1;
        }
        found = 1;
        /* scan next node */
        return 0;
    } else if (!found) {
        /* scan next node */
        return 0;
    } else if (found && depth < 2) {
        /* scanning of /reserved-memory has been finished */
        return 1;
    }

    if (!of_fdt_device_is_available(initial_boot_params, node))
        return 0;

    /*
    err = __reserved_mem_reserve_reg(node, uname);
    if (err == -ENOENT && of_get_flat_dt_prop(node, "size", NULL))
        fdt_reserved_mem_save_node(node, uname, 0, 0);
    */

    /* scan next node */
    return 0;
}

/**
 * early_init_fdt_scan_reserved_mem() - create reserved memory regions
 *
 * This function grabs memory from early allocator for device exclusive use
 * defined in device tree structures. It should be called by arch specific code
 * once the early allocator (i.e. memblock) has been fully activated.
 */
void __init early_init_fdt_scan_reserved_mem(void)
{
    int n;
    u64 base, size;

    if (!initial_boot_params)
        return;

    /* Process header /memreserve/ fields */
    for (n = 0; ; n++) {
        fdt_get_mem_rsv(initial_boot_params, n, &base, &size);
        if (!size)
            break;
        early_init_dt_reserve_memory_arch(base, size, false);
    }

    of_scan_flat_dt(__fdt_scan_reserved_mem, NULL);
    //fdt_init_reserved_mem();
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
