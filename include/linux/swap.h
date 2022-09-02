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
#include <uapi/linux/mempolicy.h>
#include <asm/page.h>

#define node_reclaim_mode 0

/*
 * current->reclaim_state points to one of these when a task is running
 * memory reclaim
 */
struct reclaim_state {
    unsigned long reclaimed_slab;
};

extern long total_swap_pages;

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

extern void free_swap_cache(struct page *);

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

extern void lru_add_drain(void);

extern void free_pages_and_swap_cache(struct page **, int);

/* linux/mm/vmscan.c */
extern unsigned long zone_reclaimable_pages(struct zone *zone);
extern unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
                                       gfp_t gfp_mask, nodemask_t *mask);
extern unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
                                                  unsigned long nr_pages,
                                                  gfp_t gfp_mask,
                                                  bool may_swap);
extern unsigned long mem_cgroup_shrink_node(struct mem_cgroup *mem,
                                            gfp_t gfp_mask, bool noswap,
                                            pg_data_t *pgdat,
                                            unsigned long *nr_scanned);

extern unsigned long shrink_all_memory(unsigned long nr_pages);
extern int vm_swappiness;
long remove_mapping(struct address_space *mapping, struct folio *folio);

/* linux/mm/swapfile.c */
extern atomic_long_t nr_swap_pages;

static inline long get_nr_swap_pages(void)
{
    return atomic_long_read(&nr_swap_pages);
}

static inline void mem_cgroup_swapout(struct folio *folio, swp_entry_t entry)
{
}

static inline int mem_cgroup_try_charge_swap(struct page *page,
                                             swp_entry_t entry)
{
    return 0;
}

static inline void mem_cgroup_uncharge_swap(swp_entry_t entry,
                                            unsigned int nr_pages)
{
}

static inline long mem_cgroup_get_nr_swap_pages(struct mem_cgroup *memcg)
{
    return get_nr_swap_pages();
}

static inline bool mem_cgroup_swap_full(struct page *page)
{
    //return vm_swap_full();
    panic("%s: END!\n", __func__);
}

static inline bool node_reclaim_enabled(void)
{
    /* Is any node_reclaim_mode bit set? */
    return node_reclaim_mode & (RECLAIM_ZONE|RECLAIM_WRITE|RECLAIM_UNMAP);
}

static inline int mem_cgroup_swappiness(struct mem_cgroup *mem)
{
    return vm_swappiness;
}

static inline int current_is_kswapd(void)
{
    return current->flags & PF_KSWAPD;
}

extern int try_to_free_swap(struct page *);

void *workingset_eviction(struct folio *folio, struct mem_cgroup *target_memcg);

/* linux/mm/swap.c */
extern void lru_note_cost(struct lruvec *lruvec, bool file,
                          unsigned int nr_pages);

void workingset_age_nonresident(struct lruvec *lruvec, unsigned long nr_pages);

extern void swap_setup(void);

#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
