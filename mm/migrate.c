// SPDX-License-Identifier: GPL-2.0
/*
 * Memory Migration functionality - linux/mm/migrate.c
 *
 * Copyright (C) 2006 Silicon Graphics, Inc., Christoph Lameter
 *
 * Page migration was first developed in the context of the memory hotplug
 * project. The main authors of the migration code are:
 *
 * IWAMOTO Toshihiro <iwamoto@valinux.co.jp>
 * Hirokazu Takahashi <taka@valinux.co.jp>
 * Dave Hansen <haveblue@us.ibm.com>
 * Christoph Lameter
 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
//#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#if 0
#include <linux/mm_inline.h>
#endif
#include <linux/nsproxy.h>
#include <linux/pagevec.h>
#if 0
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#endif
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/writeback.h>
#include <linux/vmalloc.h>
//#include <linux/security.h>
#include <linux/backing-dev.h>
//#include <linux/compaction.h>
//#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/hugetlb.h>
//#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#if 0
#include <linux/pfn_t.h>
#include <linux/memremap.h>
#include <linux/userfaultfd_k.h>
#include <linux/balloon_compaction.h>
#include <linux/page_idle.h>
#include <linux/page_owner.h>
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/memory.h>
#include <linux/sched/sysctl.h>
#endif
#include <linux/sched/mm.h>
#include <linux/random.h>

#include <asm/tlbflush.h>

#include "internal.h"

bool numa_demotion_enabled = false;

/*
 * Common logic to directly migrate a single LRU page suitable for
 * pages that do not use PagePrivate/PagePrivate2.
 *
 * Pages are locked upon entry and exit.
 */
int migrate_page(struct address_space *mapping,
                 struct page *newpage, struct page *page,
                 enum migrate_mode mode)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(migrate_page);

/*
 * Same as above except that this variant is more careful and checks that there
 * are also no buffer head references. This function is the right one for
 * mappings where buffer heads are directly looked up and referenced (such as
 * block device mappings).
 */
int buffer_migrate_page_norefs(struct address_space *mapping,
        struct page *newpage, struct page *page, enum migrate_mode mode)
{
    //return __buffer_migrate_page(mapping, newpage, page, mode, true);
    panic("%s: END!\n", __func__);
}

/*
 * Migration function for pages with buffers. This function can only be used
 * if the underlying filesystem guarantees that no other references to "page"
 * exist. For example attached buffer heads are accessed only under page lock.
 */
int buffer_migrate_page(struct address_space *mapping,
                        struct page *newpage, struct page *page,
                        enum migrate_mode mode)
{
    panic("%s: END!\n", __func__);
    //return __buffer_migrate_page(mapping, newpage, page, mode, false);
}
EXPORT_SYMBOL(buffer_migrate_page);

static struct demotion_nodes *node_demotion __read_mostly;

/**
 * next_demotion_node() - Get the next node in the demotion path
 * @node: The starting node to lookup the next node
 *
 * Return: node id for next memory node in the demotion path hierarchy
 * from @node; NUMA_NO_NODE if @node is terminal.  This does not keep
 * @node online or guarantee that it *continues* to be the next demotion
 * target.
 */
int next_demotion_node(int node)
{
    struct demotion_nodes *nd;
    unsigned short target_nr, index;
    int target;

    if (!node_demotion)
        return NUMA_NO_NODE;

    panic("%s: END!\n", __func__);
}
