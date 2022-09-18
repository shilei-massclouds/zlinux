// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 SiFive
 */

#include <asm/cacheflush.h>
#include <asm/sbi.h>

void flush_icache_all(void)
{
    local_flush_icache_all();
    sbi_remote_fence_i(NULL);
}
EXPORT_SYMBOL(flush_icache_all);

void flush_icache_pte(pte_t pte)
{
    struct page *page = pte_page(pte);

    if (!test_and_set_bit(PG_dcache_clean, &page->flags))
        flush_icache_all();
}

/*
 * Performs an icache flush for the given MM context.  RISC-V has no direct
 * mechanism for instruction cache shoot downs, so instead we send an IPI that
 * informs the remote harts they need to flush their local instruction caches.
 * To avoid pathologically slow behavior in a common case (a bunch of
 * single-hart processes on a many-hart machine, ie 'make -j') we avoid the
 * IPIs for harts that are not currently executing a MM context and instead
 * schedule a deferred local instruction cache flush to be performed before
 * execution resumes on each hart.
 */
void flush_icache_mm(struct mm_struct *mm, bool local)
{
    unsigned int cpu;
    cpumask_t others, *mask;

    panic("%s: END!\n", __func__);
}
