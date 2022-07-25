// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic hugetlb support.
 * (C) Nadia Yvette Chambers, April 2004
 */
#include <linux/list.h>
#include <linux/init.h>
#include <linux/mm.h>
#if 0
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/mmu_notifier.h>
#endif
#include <linux/highmem.h>
#include <linux/nodemask.h>
#include <linux/pagemap.h>
#if 0
#include <linux/mempolicy.h>
#include <linux/sysfs.h>
#include <linux/cpuset.h>
#include <linux/rmap.h>
#include <linux/jhash.h>
#endif
#include <linux/compiler.h>
#include <linux/mutex.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/mmdebug.h>
#include <linux/sched/signal.h>
#include <linux/string_helpers.h>
#include <linux/swap.h>
#include <linux/numa.h>
#include <linux/llist.h>
#if 0
#include <linux/migrate.h>
#include <linux/cma.h>
#include <linux/swapops.h>
#include <linux/nospec.h>
#endif

#include <asm/page.h>

#include <asm/pgalloc.h>
#if 0
#include <asm/tlb.h>
#endif

#include <linux/io.h>
#include <linux/hugetlb.h>
#if 0
#include <linux/hugetlb_cgroup.h>
#include <linux/node.h>
#include <linux/page_owner.h>
#endif
#include "internal.h"
//#include "hugetlb_vmemmap.h"

/*
 * PageHeadHuge() only returns true for hugetlbfs head page, but not for
 * normal or transparent huge pages.
 */
int PageHeadHuge(struct page *page_head)
{
    if (!PageHead(page_head))
        return 0;

    return page_head[1].compound_dtor == HUGETLB_PAGE_DTOR;
}
EXPORT_SYMBOL_GPL(PageHeadHuge);
