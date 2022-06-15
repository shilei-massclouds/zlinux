/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/mmdebug.h>
#include <linux/gfp.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/mmzone.h>
//#include <linux/rbtree.h>
#include <linux/atomic.h>
//#include <linux/debug_locks.h>
#include <linux/mm_types.h>
//#include <linux/mmap_lock.h>
//#include <linux/range.h>
#include <linux/pfn.h>
//#include <linux/percpu-refcount.h>
//#include <linux/bit_spinlock.h>
//#include <linux/shrinker.h>
//#include <linux/resource.h>
//#include <linux/page_ext.h>
#include <linux/err.h>
#include <linux/page-flags.h>
#include <linux/page_ref.h>
#include <linux/memremap.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <linux/jump_label.h>

#include <asm/page.h>

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
#define PAGE_ALIGNED(addr)  IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

/* Page flags: | [SECTION] | [NODE] | ZONE | [LAST_CPUPID] | ... | FLAGS | */
#define SECTIONS_PGOFF      ((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF         (SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF         (NODES_PGOFF - ZONES_WIDTH)
#define LAST_CPUPID_PGOFF   (ZONES_PGOFF - LAST_CPUPID_WIDTH)

#define NODES_PGSHIFT       (NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT       (ZONES_PGOFF * (ZONES_WIDTH != 0))
#define LAST_CPUPID_PGSHIFT (LAST_CPUPID_PGOFF * (LAST_CPUPID_WIDTH != 0))

#define ZONES_MASK          ((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK          ((1UL << NODES_WIDTH) - 1)
#define LAST_CPUPID_MASK    ((1UL << LAST_CPUPID_SHIFT) - 1)

#define ZONEID_SHIFT (NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF ((NODES_PGOFF < ZONES_PGOFF)? NODES_PGOFF : ZONES_PGOFF)

#define ZONEID_MASK ((1UL << ZONEID_SHIFT) - 1)

#define ZONEID_PGSHIFT (ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#ifndef lm_alias
#define lm_alias(x) __va(__pa_symbol(x))
#endif

extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
    max_mapnr = limit;
}

void free_area_init(unsigned long *max_zone_pfn);

extern void get_pfn_range_for_nid(unsigned int nid,
                                  unsigned long *start_pfn, unsigned long *end_pfn);

/* This function must be updated when the size of struct page grows above 80
 * or reduces below 56. The idea that compiler optimizes out switch()
 * statement, and only leaves move/store instructions. Also the compiler can
 * combine write statements if they are both assignments and can be reordered,
 * this can result in several of the writes here being dropped.
 */
#define mm_zero_struct_page(pp) __mm_zero_struct_page(pp)
static inline void __mm_zero_struct_page(struct page *page)
{
    unsigned long *_pp = (void *)page;

     /* Check that struct page is either 56, 64, 72, or 80 bytes */
    BUILD_BUG_ON(sizeof(struct page) & 7);
    //BUILD_BUG_ON(sizeof(struct page) < 56);
    BUILD_BUG_ON(sizeof(struct page) > 80);

    switch (sizeof(struct page)) {
    case 80:
        _pp[9] = 0;
        fallthrough;
    case 72:
        _pp[8] = 0;
        fallthrough;
    case 64:
        _pp[7] = 0;
        fallthrough;
    case 56:
        _pp[6] = 0;
        _pp[5] = 0;
        _pp[4] = 0;
        _pp[3] = 0;
        _pp[2] = 0;
        _pp[1] = 0;
        _pp[0] = 0;
    }
}

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
    page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
    page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
    page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
    page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void
set_page_links(struct page *page, enum zone_type zone,
               unsigned long node, unsigned long pfn)
{
    set_page_zone(page, zone);
    set_page_node(page, node);
}

static inline int page_cpupid_last(struct page *page)
{
    return (page->flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK;
}

static inline void page_cpupid_reset_last(struct page *page)
{
    page->flags |= LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT;
}

/*
 * The atomic page->_mapcount, starts from -1: so that transitions
 * both from it and to it can be tracked, using atomic_inc_and_test
 * and atomic_add_negative(-1).
 */
static inline void page_mapcount_reset(struct page *page)
{
    atomic_set(&(page)->_mapcount, -1);
}

static inline enum zone_type page_zonenum(const struct page *page)
{
    return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

static inline int page_to_nid(const struct page *page)
{
    struct page *p = (struct page *)page;

    return (PF_POISONED_CHECK(p)->flags >> NODES_PGSHIFT) & NODES_MASK;
}

static inline struct zone *page_zone(const struct page *page)
{
    return &NODE_DATA(page_to_nid(page))->node_zones[page_zonenum(page)];
}

extern void mem_init(void);
extern void mem_init_print_info(void);

extern atomic_long_t _totalram_pages;

static inline void totalram_pages_add(long count)
{
    atomic_long_add(count, &_totalram_pages);
}

extern void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);

extern void *high_memory;

/*
 * The identification function is mainly used by the buddy allocator for
 * determining if two pages could be buddies. We are not really identifying
 * the zone since we could be using the section number id if we do not have
 * node id available in page flags.
 * We only guarantee that it will return the same value for two combinable
 * pages in a zone.
 */
static inline int page_zone_id(struct page *page)
{
    return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

extern void setup_per_cpu_pageset(void);

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
static inline bool want_init_on_alloc(gfp_t flags)
{
    if (static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, &init_on_alloc))
        return true;

    return flags & __GFP_ZERO;
}

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_FREE_DEFAULT_ON, init_on_free);
static inline bool want_init_on_free(void)
{
    return static_branch_maybe(CONFIG_INIT_ON_FREE_DEFAULT_ON, &init_on_free);
}

static inline u8 page_kasan_tag(const struct page *page)
{
    return 0xff;
}

static __always_inline void *lowmem_page_address(const struct page *page)
{
    return page_to_virt(page);
}

#define page_address(page) lowmem_page_address(page)

/* Keep the enum in sync with compound_page_dtors array in mm/page_alloc.c */
enum compound_dtor_id {
    NULL_COMPOUND_DTOR,
    COMPOUND_PAGE_DTOR,
    NR_COMPOUND_DTORS,
};

static inline void
set_compound_page_dtor(struct page *page, enum compound_dtor_id compound_dtor)
{
    VM_BUG_ON_PAGE(compound_dtor >= NR_COMPOUND_DTORS, page);
    page[1].compound_dtor = compound_dtor;
}

static inline unsigned int compound_order(struct page *page)
{
    if (!PageHead(page))
        return 0;
    return page[1].compound_order;
}

static inline bool hpage_pincount_available(struct page *page)
{
    /*
     * Can the page->hpage_pinned_refcount field be used? That field is in
     * the 3rd page of the compound page, so the smallest (2-page) compound
     * pages cannot support it.
     */
    page = compound_head(page);
    return PageCompound(page) && compound_order(page) > 1;
}

static inline void set_compound_order(struct page *page, unsigned int order)
{
    page[1].compound_order = order;
    page[1].compound_nr = 1U << order;
}

/*
 * Only to be called by the page allocator on a freshly allocated
 * page.
 */
static inline void set_page_pfmemalloc(struct page *page)
{
    page->lru.next = (void *)BIT(1);
}

static inline void clear_page_pfmemalloc(struct page *page)
{
    page->lru.next = NULL;
}

/*
 * Drop a ref, return true if the refcount fell to zero (the page has no users)
 */
static inline int put_page_testzero(struct page *page)
{
    VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);
    return page_ref_dec_and_test(page);
}

static inline pg_data_t *page_pgdat(const struct page *page)
{
    return NODE_DATA(page_to_nid(page));
}

extern atomic_long_t _totalram_pages;
static inline unsigned long totalram_pages(void)
{
    return (unsigned long)atomic_long_read(&_totalram_pages);
}

static inline struct page *virt_to_head_page(const void *x)
{
    struct page *page = virt_to_page(x);

    return compound_head(page);
}

void setup_initial_init_mm(void *start_code, void *end_code,
                           void *end_data, void *brk);

/*
 * Some inline functions in vmstat.h depend on page_zone()
 */
#include <linux/vmstat.h>

#define offset_in_page(p)       ((unsigned long)(p) & ~PAGE_MASK)

#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
#error "NOT SUPPORT ALLOC_SPLIT_PTLOCKS!"
#else /* ALLOC_SPLIT_PTLOCKS */
#endif /* ALLOC_SPLIT_PTLOCKS */

static inline spinlock_t *ptlock_ptr(struct page *page)
{
    return &page->ptl;
}

static inline bool ptlock_init(struct page *page)
{
    /*
     * prep_new_page() initialize page->private (and therefore page->ptl)
     * with 0. Make sure nobody took it in use in between.
     *
     * It can happen if arch try to use slab for page table allocation:
     * slab code uses page->slab_cache, which share storage with page->ptl.
     */
    VM_BUG_ON_PAGE(*(unsigned long *)&page->ptl, page);
    spin_lock_init(ptlock_ptr(page));
    return true;
}

#else /* !USE_SPLIT_PTE_PTLOCKS */
#error "NO USE_SPLIT_PTE_PTLOCKS!"
#endif /* USE_SPLIT_PTE_PTLOCKS */

#if USE_SPLIT_PMD_PTLOCKS

static inline bool pmd_ptlock_init(struct page *page)
{
    return ptlock_init(page);
}

#else /* !USE_SPLIT_PMD_PTLOCKS */
#error "NO USE_SPLIT_PMD_PTLOCKS!"
#endif /* USE_SPLIT_PMD_PTLOCKS */

static inline bool pgtable_pte_page_ctor(struct page *page)
{
    if (!ptlock_init(page))
        return false;
    __SetPageTable(page);
    inc_lruvec_page_state(page, NR_PAGETABLE);
    return true;
}

static inline bool pgtable_pmd_page_ctor(struct page *page)
{
    if (!pmd_ptlock_init(page))
        return false;
    __SetPageTable(page);
    inc_lruvec_page_state(page, NR_PAGETABLE);
    return true;
}

static inline unsigned long get_num_physpages(void)
{
    int nid;
    unsigned long phys_pages = 0;

    for_each_online_node(nid)
        phys_pages += node_present_pages(nid);

    return phys_pages;
}

extern __printf(3, 4)
void warn_alloc(gfp_t gfp_mask, nodemask_t *nodemask, const char *fmt, ...);

#endif /* _LINUX_MM_H */
