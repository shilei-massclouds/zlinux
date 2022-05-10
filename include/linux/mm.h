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
//#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/pgtable.h>

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

extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
    max_mapnr = limit;
}

void free_area_init(unsigned long *max_zone_pfn);

static inline void setup_nr_node_ids(void) {}

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

#endif /* _LINUX_MM_H */
