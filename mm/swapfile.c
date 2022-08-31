// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/swapfile.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
//#include <linux/blk-cgroup.h>
#include <linux/random.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
//#include <linux/seq_file.h>
#include <linux/init.h>
//#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/security.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
//#include <linux/capability.h>
#include <linux/syscalls.h>
#include <linux/memcontrol.h>
//#include <linux/poll.h>
#include <linux/oom.h>
//#include <linux/frontswap.h>
//#include <linux/swapfile.h>
#include <linux/export.h>
//#include <linux/swap_slots.h>
//#include <linux/sort.h>
#include <linux/completion.h>

#include <asm/tlbflush.h>
#include <linux/swapops.h>
//#include <linux/swap_cgroup.h>

static unsigned int nr_swapfiles;
atomic_long_t nr_swap_pages;

/* protected with swap_lock. reading in vm_swap_full() doesn't need lock */
long total_swap_pages;

/*
 * If swap is getting full, or if there are no more mappings of this page,
 * then try_to_free_swap is called to free its swap space.
 */
int try_to_free_swap(struct page *page)
{
    panic("%s: END!\n", __func__);
}
