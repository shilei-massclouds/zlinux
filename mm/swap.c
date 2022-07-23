// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/admin-guide/sysctl/vm.rst.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
//#include <linux/mman.h>
#include <linux/pagemap.h>
//#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
//#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
//#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
//#include <linux/notifier.h>
#include <linux/backing-dev.h>
//#include <linux/memcontrol.h>
#include <linux/gfp.h>
#if 0
#include <linux/uio.h>
#include <linux/hugetlb.h>
#include <linux/page_idle.h>
#include <linux/buffer_head.h>
#endif
#include <linux/local_lock.h>

#include "internal.h"

static void __put_single_page(struct page *page)
{
#if 0
    __page_cache_release(page);
    free_unref_page(page, 0);
#endif
    pr_warn("%s: END!\n", __func__);
}

static void __put_compound_page(struct page *page)
{
    /*
     * __page_cache_release() is supposed to be called for thp, not for
     * hugetlb. This is because hugetlb page does never have PageLRU set
     * (it's never listed to any LRU lists) and no memcg routines should
     * be called for hugetlb (it has a separate hugetlb_cgroup.)
     */
#if 0
    if (!PageHuge(page))
        __page_cache_release(page);
    destroy_compound_page(page);
#endif
    pr_warn("%s: END!\n", __func__);
}

void __put_page(struct page *page)
{
    if (unlikely(PageCompound(page)))
        __put_compound_page(page);
    else
        __put_single_page(page);
}
EXPORT_SYMBOL(__put_page);
