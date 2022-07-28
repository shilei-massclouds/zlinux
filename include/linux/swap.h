/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>
#include <linux/fs.h>
//#include <linux/node.h>
#include <linux/pagemap.h>
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

void workingset_refault(struct folio *folio, void *shadow);

extern void folio_add_lru(struct folio *);

extern atomic_t lru_disable_count;

static inline bool lru_cache_disabled(void)
{
    return atomic_read(&lru_disable_count);
}

static inline void lru_cache_enable(void)
{
    atomic_dec(&lru_disable_count);
}

/* Only track the nodes of mappings with shadow entries */
void workingset_update_node(struct xa_node *node);
extern struct list_lru shadow_nodes;
#define mapping_set_update(xas, mapping) do {               \
    if (!shmem_mapping(mapping)) {     \
        xas_set_update(xas, workingset_update_node);        \
        xas_set_lru(xas, &shadow_nodes);            \
    }                               \
} while (0)

void folio_mark_accessed(struct folio *);

#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
