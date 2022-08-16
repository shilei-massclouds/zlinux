/* SPDX-License-Identifier: GPL-2.0-or-later */
/* internal.h: mm/ internal definitions
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef __MM_INTERNAL_H
#define __MM_INTERNAL_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

/*
 * The set of flags that only affect watermark checking and reclaim
 * behaviour. This is used by the MM to obey the caller constraints
 * about IO, FS and watermark checking while ignoring placement
 * hints such as HIGHMEM usage.
 */
#define GFP_RECLAIM_MASK \
    (__GFP_RECLAIM|__GFP_HIGH|__GFP_IO|__GFP_FS| \
     __GFP_NOWARN|__GFP_RETRY_MAYFAIL|__GFP_NOFAIL| \
     __GFP_NORETRY|__GFP_MEMALLOC|__GFP_NOMEMALLOC| __GFP_ATOMIC)

/* Control allocation cpuset and node placement constraints */
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)

/* Do not use these with a slab allocator */
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)

/*
 * Structure for holding the mostly immutable allocation parameters passed
 * between functions involved in allocations, including the alloc_pages*
 * family of functions.
 *
 * nodemask, migratetype and highest_zoneidx are initialized only once in
 * __alloc_pages() and then never change.
 *
 * zonelist, preferred_zone and highest_zoneidx are set first in
 * __alloc_pages() for the fast path, and might be later changed
 * in __alloc_pages_slowpath(). All other functions pass the whole structure
 * by a const pointer.
 */
struct alloc_context {
    struct zonelist *zonelist;
    nodemask_t *nodemask;
    struct zoneref *preferred_zoneref;
    int migratetype;

    /*
     * highest_zoneidx represents highest usable zone index of
     * the allocation request. Due to the nature of the zone,
     * memory on lower zone than the highest_zoneidx will be
     * protected by lowmem_reserve[highest_zoneidx].
     *
     * highest_zoneidx is also used by reclaim/compaction to limit
     * the target zone since higher zone than this index cannot be
     * usable for this allocation request.
     */
    enum zone_type highest_zoneidx;
    bool spread_dirty_pages;
};

extern unsigned long highest_memmap_pfn;

#define ALLOC_OOM           0x08

#define ALLOC_HARDER        0x10 /* try to alloc harder */

/* The GFP flags allowed during early boot */
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GFP_FS))

/* The ALLOC_WMARK bits are used as an index to zone->watermark */
#define ALLOC_WMARK_MIN     WMARK_MIN
#define ALLOC_WMARK_LOW     WMARK_LOW
#define ALLOC_WMARK_HIGH    WMARK_HIGH
#define ALLOC_NO_WATERMARKS 0x04    /* don't check watermarks at all */

#define ALLOC_NOFRAGMENT    0x100   /* avoid mixing pageblock types */

/* Mask to get the watermark bits */
#define ALLOC_WMARK_MASK    (ALLOC_NO_WATERMARKS-1)

static inline int
find_next_best_node(int node, nodemask_t *used_node_mask)
{
    return NUMA_NO_NODE;
}

extern void
memblock_free_pages(struct page *page, unsigned long pfn,
                    unsigned int order);

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 */
static inline unsigned long
__find_buddy_pfn(unsigned long page_pfn, unsigned int order)
{
    return page_pfn ^ (1 << order);
}

/*
 * This function returns the order of a free page in the buddy system. In
 * general, page_zone(page)->lock must be held by the caller to prevent the
 * page from being allocated in parallel and returning garbage as the order.
 * If a caller does not hold page_zone(page)->lock, it must guarantee that the
 * page cannot be allocated or merged in parallel. Alternatively, it must
 * handle invalid values gracefully, and use buddy_order_unsafe() below.
 */
static inline unsigned int buddy_order(struct page *page)
{
    /* PageBuddy() must be checked by the caller */
    return page_private(page);
}

static inline bool is_migrate_highatomic(enum migratetype migratetype)
{
    return migratetype == MIGRATE_HIGHATOMIC;
}

/*
 * Turn a non-refcounted page (->_refcount == 0) into refcounted with
 * a count of one.
 */
static inline void set_page_refcounted(struct page *page)
{
    VM_BUG_ON_PAGE(PageTail(page), page);
    VM_BUG_ON_PAGE(page_ref_count(page), page);
    set_page_count(page, 1);
}

int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
                             pgprot_t prot, struct page **pages,
                             unsigned int page_shift);

void vunmap_range_noflush(unsigned long start, unsigned long end);

unsigned find_lock_entries(struct address_space *mapping,
                           pgoff_t start, pgoff_t end,
                           struct folio_batch *fbatch, pgoff_t *indices);

void unmap_mapping_folio(struct folio *folio);

extern void free_unref_page_list(struct list_head *list);

unsigned find_get_entries(struct address_space *mapping,
                          pgoff_t start, pgoff_t end,
                          struct folio_batch *fbatch, pgoff_t *indices);

/* mm/util.c */
void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
                     struct vm_area_struct *prev);
void __vma_unlink_list(struct mm_struct *mm, struct vm_area_struct *vma);

extern long populate_vma_page_range(struct vm_area_struct *vma,
                                    unsigned long start, unsigned long end,
                                    int *locked);

void mlock_new_page(struct page *page);

/**
 * folio_evictable - Test whether a folio is evictable.
 * @folio: The folio to test.
 *
 * Test whether @folio is evictable -- i.e., should be placed on
 * active/inactive lists vs unevictable list.
 *
 * Reasons folio might not be evictable:
 * 1. folio's mapping marked unevictable
 * 2. One of the pages in the folio is part of an mlocked VMA
 */
static inline bool folio_evictable(struct folio *folio)
{
    bool ret;

    /* Prevent address_space of inode and swap cache from being freed */
    rcu_read_lock();
    ret = !mapping_unevictable(folio_mapping(folio)) &&
        !folio_test_mlocked(folio);
    rcu_read_unlock();
    return ret;
}

static inline bool page_evictable(struct page *page)
{
    bool ret;

    /* Prevent address_space of inode and swap cache from being freed */
    rcu_read_lock();
    ret = !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
    rcu_read_unlock();
    return ret;
}

/*
 * Executable code area - executable, not writable, not stack
 */
static inline bool is_exec_mapping(vm_flags_t flags)
{
    return (flags & (VM_EXEC | VM_WRITE | VM_STACK)) == VM_EXEC;
}

/*
 * Stack area - automatically grows in one direction
 *
 * VM_GROWSUP / VM_GROWSDOWN VMAs are always private anonymous:
 * do_mmap() forbids all other combinations.
 */
static inline bool is_stack_mapping(vm_flags_t flags)
{
    return (flags & VM_STACK) == VM_STACK;
}

/*
 * Data area - private, writable, not stack
 */
static inline bool is_data_mapping(vm_flags_t flags)
{
    return (flags & (VM_WRITE | VM_SHARED | VM_STACK)) == VM_WRITE;
}

extern int mlock_future_check(struct mm_struct *mm, unsigned long flags,
                              unsigned long len);

static inline struct file *maybe_unlock_mmap_for_io(struct vm_fault *vmf,
                            struct file *fpin)
{
    int flags = vmf->flags;

    if (fpin)
        return fpin;

    /*
     * FAULT_FLAG_RETRY_NOWAIT means we don't want to wait on page locks or
     * anything, so we only pin the file and drop the mmap_lock if only
     * FAULT_FLAG_ALLOW_RETRY is set, while this is the first attempt.
     */
    if (fault_flag_allow_retry_first(flags) &&
        !(flags & FAULT_FLAG_RETRY_NOWAIT)) {
        fpin = get_file(vmf->vma->vm_file);
        mmap_read_unlock(vmf->vma->vm_mm);
    }
    return fpin;
}

void page_cache_ra_order(struct readahead_control *, struct file_ra_state *,
                         unsigned int order);

void pmd_install(struct mm_struct *mm, pmd_t *pmd, pgtable_t *pte);

/*
 * mlock_vma_page() and munlock_vma_page():
 * should be called with vma's mmap_lock held for read or write,
 * under page table lock for the pte/pmd being added or removed.
 *
 * mlock is usually called at the end of page_add_*_rmap(),
 * munlock at the end of page_remove_rmap(); but new anon
 * pages are managed by lru_cache_add_inactive_or_unevictable()
 * calling mlock_new_page().
 *
 * @compound is used to include pmd mappings of THPs, but filter out
 * pte mappings of THPs, which cannot be consistently counted: a pte
 * mapping of the THP head cannot be distinguished by the page alone.
 */
void mlock_folio(struct folio *folio);
static inline void mlock_vma_folio(struct folio *folio,
                                   struct vm_area_struct *vma, bool compound)
{
    /*
     * The VM_SPECIAL check here serves two purposes.
     * 1) VM_IO check prevents migration from double-counting during mlock.
     * 2) Although mmap_region() and mlock_fixup() take care that VM_LOCKED
     *    is never left set on a VM_SPECIAL vma, there is an interval while
     *    file->f_op->mmap() is using vm_insert_page(s), when VM_LOCKED may
     *    still be set while VM_SPECIAL bits are added: so ignore it then.
     */
    if (unlikely((vma->vm_flags & (VM_LOCKED|VM_SPECIAL)) == VM_LOCKED) &&
        (compound || !folio_test_large(folio)))
        mlock_folio(folio);
}

static inline void mlock_vma_page(struct page *page,
                                  struct vm_area_struct *vma, bool compound)
{
    mlock_vma_folio(page_folio(page), vma, compound);
}

extern void free_unref_page(struct page *page, unsigned int order);

#endif  /* __MM_INTERNAL_H */
