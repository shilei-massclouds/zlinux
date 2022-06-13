/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>
/*
#include <linux/node.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
*/
#include <linux/atomic.h>
#include <linux/page-flags.h>
//#include <uapi/linux/mempolicy.h>
#include <asm/page.h>

/*
 * current->reclaim_state points to one of these when a task is running
 * memory reclaim
 */
struct reclaim_state {
    unsigned long reclaimed_slab;
};

/* Definition of global_zone_page_state not available yet */
#define nr_free_pages() global_zone_page_state(NR_FREE_PAGES)

#ifdef __KERNEL__

#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
