// SPDX-License-Identifier: GPL-2.0+
/*
 * Device tree based initialization code for reserved memory.
 *
 * Copyright (c) 2013, 2015 The Linux Foundation. All Rights Reserved.
 * Copyright (c) 2013,2014 Samsung Electronics Co., Ltd.
 *      http://www.samsung.com
 * Author: Marek Szyprowski <m.szyprowski@samsung.com>
 * Author: Josh Cartwright <joshc@codeaurora.org>
 */

#define pr_fmt(fmt) "OF: reserved mem: " fmt

#include <linux/err.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
//#include <linux/of_platform.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/of_reserved_mem.h>
//#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/memblock.h>
/*
#include <linux/kmemleak.h>
#include <linux/cma.h>
*/

#include "of_private.h"

#define MAX_RESERVED_REGIONS    64
static struct reserved_mem reserved_mem[MAX_RESERVED_REGIONS];
static int reserved_mem_count;

/*
 * fdt_reserved_mem_save_node() - save fdt node for second pass initialization
 */
void __init fdt_reserved_mem_save_node(unsigned long node, const char *uname,
                                       phys_addr_t base, phys_addr_t size)
{
    struct reserved_mem *rmem = &reserved_mem[reserved_mem_count];

    if (reserved_mem_count == ARRAY_SIZE(reserved_mem)) {
        pr_err("not enough space for all defined regions.\n");
        return;
    }

    rmem->fdt_node = node;
    rmem->name = uname;
    rmem->base = base;
    rmem->size = size;

    reserved_mem_count++;
    return;
}

static void __init __rmem_check_for_overlap(void)
{
    int i;

    if (reserved_mem_count < 2)
        return;

    panic("%s: END!\n", __func__);
#if 0
    sort(reserved_mem, reserved_mem_count, sizeof(reserved_mem[0]),
         __rmem_cmp, NULL);

    for (i = 0; i < reserved_mem_count - 1; i++) {
        struct reserved_mem *this, *next;

        this = &reserved_mem[i];
        next = &reserved_mem[i + 1];

        if (this->base + this->size > next->base) {
            phys_addr_t this_end, next_end;

            this_end = this->base + this->size;
            next_end = next->base + next->size;
            pr_err("OVERLAP DETECTED!\n%s (%pa--%pa) overlaps with %s (%pa--%pa)\n",
                   this->name, &this->base, &this_end,
                   next->name, &next->base, &next_end);
        }
    }
#endif
}

/*
 * __reserved_mem_alloc_size() - allocate reserved memory described by
 *  'size', 'alignment'  and 'alloc-ranges' properties.
 */
static int __init
__reserved_mem_alloc_size(unsigned long node, const char *uname,
                          phys_addr_t *res_base, phys_addr_t *res_size)
{
    int ret;
    phys_addr_t start = 0, end = 0;
    phys_addr_t base = 0, align = 0, size;
    int len;
    const __be32 *prop;
    bool nomap;
    int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);

    prop = of_get_flat_dt_prop(node, "size", &len);
    if (!prop)
        return -EINVAL;

    if (len != dt_root_size_cells * sizeof(__be32)) {
        pr_err("invalid size property in '%s' node.\n", uname);
        return -EINVAL;
    }
    size = dt_mem_next_cell(dt_root_size_cells, &prop);

    panic("%s: size(%lx) END!\n", __func__, size);
}

/*
 * __reserved_mem_init_node() - call region specific reserved memory init code
 */
static int __init __reserved_mem_init_node(struct reserved_mem *rmem)
{
    return 0;
#if 0
    int ret = -ENOENT;
    const struct of_device_id *i;
    extern const struct of_device_id __reservedmem_of_table[];

    for (i = __reservedmem_of_table; i < &__rmem_of_table_sentinel; i++) {
        reservedmem_of_init_fn initfn = i->data;
        const char *compat = i->compatible;

        if (!of_flat_dt_is_compatible(rmem->fdt_node, compat))
            continue;

        ret = initfn(rmem);
        if (ret == 0) {
            pr_info("initialized node %s, compatible id %s\n",
                rmem->name, compat);
            break;
        }
    }
    return ret;
#endif
}

/**
 * fdt_init_reserved_mem() - allocate and init all saved reserved memory regions
 */
void __init fdt_init_reserved_mem(void)
{
    int i;

    /* check for overlapping reserved regions */
    __rmem_check_for_overlap();

    for (i = 0; i < reserved_mem_count; i++) {
        int len;
        bool nomap;
        int err = 0;
        const __be32 *prop;
        struct reserved_mem *rmem = &reserved_mem[i];
        unsigned long node = rmem->fdt_node;

        nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;
        prop = of_get_flat_dt_prop(node, "phandle", &len);
        if (!prop)
            prop = of_get_flat_dt_prop(node, "linux,phandle", &len);
        if (prop)
            rmem->phandle = of_read_number(prop, len/4);

        if (rmem->size == 0)
            err = __reserved_mem_alloc_size(node, rmem->name,
                                            &rmem->base, &rmem->size);
        if (err == 0) {
            err = __reserved_mem_init_node(rmem);
            if (err != 0 && err != -ENOENT) {
                panic("node %s compatible matching fail\n", rmem->name);
            }
        }
    }
}
