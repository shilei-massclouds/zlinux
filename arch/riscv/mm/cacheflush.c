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
