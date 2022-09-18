// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <asm/cacheinfo.h>

uintptr_t get_cache_size(u32 level, enum cache_type type)
{
#if 0
    struct cacheinfo *this_leaf = get_cacheinfo(level, type);

    return this_leaf ? this_leaf->size : 0;
#endif
    panic("%s: END!\n", __func__);
}

uintptr_t get_cache_geometry(u32 level, enum cache_type type)
{
#if 0
    struct cacheinfo *this_leaf = get_cacheinfo(level, type);

    return this_leaf ?
        (this_leaf->ways_of_associativity << 16 |
         this_leaf->coherency_line_size) : 0;
#endif

    panic("%s: END!\n", __func__);
}
