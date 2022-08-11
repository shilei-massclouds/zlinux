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

/*
 * MAX_SWAPFILES defines the maximum number of swaptypes: things which can
 * be swapped to.  The swap type and the offset into that swap type are
 * encoded into pte's and into pgoff_t's in the swapcache.  Using five bits
 * for the type means that the maximum number of swapcache pages is 27 bits
 * on 32-bit-pgoff_t architectures.  And that assumes that the architecture packs
 * the type/offset into the pte as 5/27 as well.
 */
#define MAX_SWAPFILES_SHIFT 5

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

void mark_page_accessed(struct page *);

#define SWAP_CLUSTER_MAX 32UL
#define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX

extern void
lru_cache_add_inactive_or_unevictable(struct page *page,
                                      struct vm_area_struct *vma);

extern void lru_cache_add(struct page *);

/* linux/mm/swap_state.c */
/* One swap address space for each 64M swap space */
#define SWAP_ADDRESS_SPACE_SHIFT    14
#define SWAP_ADDRESS_SPACE_PAGES    (1 << SWAP_ADDRESS_SPACE_SHIFT)
extern struct address_space *swapper_spaces[];
#define swap_address_space(entry) \
    (&swapper_spaces[swp_type(entry)][swp_offset(entry) \
     >> SWAP_ADDRESS_SPACE_SHIFT])

static inline swp_entry_t folio_swap_entry(struct folio *folio)
{
    swp_entry_t entry = { .val = page_private(&folio->page) };
    return entry;
}

/*
 * Unaddressable device memory support. See include/linux/hmm.h and
 * Documentation/vm/hmm.rst. Short description is we need struct pages for
 * device memory that is unaddressable (inaccessible) by CPU, so that we can
 * migrate part of a process memory to device memory.
 *
 * When a page is migrated from CPU to device, we set the CPU page table entry
 * to a special SWP_DEVICE_{READ|WRITE} entry.
 *
 * When a page is mapped by the device for exclusive access we set the CPU page
 * table entries to special SWP_DEVICE_EXCLUSIVE_* entries.
 */
#define SWP_DEVICE_NUM 0

/*
 * NUMA node memory migration support
 */
#define SWP_MIGRATION_NUM 2
#define SWP_MIGRATION_READ  (MAX_SWAPFILES + SWP_HWPOISON_NUM)
#define SWP_MIGRATION_WRITE (MAX_SWAPFILES + SWP_HWPOISON_NUM + 1)

/*
 * Handling of hardware poisoned pages with memory corruption.
 */
#define SWP_HWPOISON_NUM 0

#define MAX_SWAPFILES \
    ((1 << MAX_SWAPFILES_SHIFT) - SWP_DEVICE_NUM - \
    SWP_MIGRATION_NUM - SWP_HWPOISON_NUM)

#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
