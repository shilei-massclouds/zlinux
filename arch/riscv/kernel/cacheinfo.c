// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <asm/cacheinfo.h>

static struct cacheinfo *get_cacheinfo(u32 level, enum cache_type type)
{
    /*
     * Using raw_smp_processor_id() elides a preemptability check, but this
     * is really indicative of a larger problem: the cacheinfo UABI assumes
     * that cores have a homonogenous view of the cache hierarchy.  That
     * happens to be the case for the current set of RISC-V systems, but
     * likely won't be true in general.  Since there's no way to provide
     * correct information for these systems via the current UABI we're
     * just eliding the check for now.
     */
    struct cpu_cacheinfo *this_cpu_ci =
        get_cpu_cacheinfo(raw_smp_processor_id());
    struct cacheinfo *this_leaf;
    int index;

    for (index = 0; index < this_cpu_ci->num_leaves; index++) {
        this_leaf = this_cpu_ci->info_list + index;
        if (this_leaf->level == level && this_leaf->type == type)
            return this_leaf;
    }

    return NULL;
}

uintptr_t get_cache_size(u32 level, enum cache_type type)
{
    struct cacheinfo *this_leaf = get_cacheinfo(level, type);

    return this_leaf ? this_leaf->size : 0;
}

uintptr_t get_cache_geometry(u32 level, enum cache_type type)
{
    struct cacheinfo *this_leaf = get_cacheinfo(level, type);

    return this_leaf ?
        (this_leaf->ways_of_associativity << 16 |
         this_leaf->coherency_line_size) : 0;
}
