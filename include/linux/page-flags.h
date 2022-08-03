/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Macros for manipulating and testing page->flags
 */

#ifndef PAGE_FLAGS_H
#define PAGE_FLAGS_H

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/mmdebug.h>
#ifndef __GENERATING_BOUNDS_H
#include <linux/mm_types.h>
#include <generated/bounds.h>
#endif /* !__GENERATING_BOUNDS_H */

/*
 * Don't use the pageflags directly.  Use the PageFoo macros.
 *
 * The page flags field is split into two parts, the main flags area
 * which extends from the low bits upwards, and the fields area which
 * extends from the high bits downwards.
 *
 *  | FIELD | ... | FLAGS |
 *  N-1           ^       0
 *               (NR_PAGEFLAGS)
 *
 * The fields area is reserved for fields mapping zone, node (for NUMA) and
 * SPARSEMEM section (for variants of SPARSEMEM that require section ids like
 * SPARSEMEM_EXTREME with !SPARSEMEM_VMEMMAP).
 */
enum pageflags {
    PG_locked,      /* Page is locked. Don't touch. */
    PG_referenced,
    PG_uptodate,
    PG_dirty,
    PG_lru,
    PG_active,
    PG_workingset,
    PG_waiters,     /* Page has waiters, check its waitqueue.
                       Must be bit #7 and in the same byte as "PG_locked" */
    PG_error,
    PG_slab,
    PG_owner_priv_1,    /* Owner use. If pagecache, fs may use*/
    PG_arch_1,
    PG_reserved,
    PG_private,     /* If pagecache, has fs-private data */
    PG_private_2,   /* If pagecache, has fs aux data */
    PG_writeback,   /* Page is under writeback */
    PG_head,        /* A head page */
    PG_mappedtodisk,    /* Has blocks allocated on-disk */
    PG_reclaim,     /* To be reclaimed asap */
    PG_swapbacked,  /* Page is backed by RAM/swap */
    PG_unevictable, /* Page is "unevictable"  */
    PG_mlocked,     /* Page is vma mlocked */

    __NR_PAGEFLAGS,
};

#define PAGEFLAGS_MASK  ((1UL << NR_PAGEFLAGS) - 1)

#ifndef __GENERATING_BOUNDS_H

unsigned long get_pfnblock_flags_mask(const struct page *page,
                                      unsigned long pfn, unsigned long mask);

static inline unsigned long _compound_head(const struct page *page)
{
    unsigned long head = READ_ONCE(page->compound_head);

    if (unlikely(head & 1))
        return head - 1;
    return (unsigned long)page;
}

#define compound_head(page) ((typeof(page))_compound_head(page))

/**
 * page_folio - Converts from page to folio.
 * @p: The page.
 *
 * Every page is part of a folio.  This function cannot be called on a
 * NULL pointer.
 *
 * Context: No reference, nor lock is required on @page.  If the caller
 * does not hold a reference, this call may race with a folio split, so
 * it should re-check the folio still contains this page after gaining
 * a reference on the folio.
 * Return: The folio which contains this page.
 */
#define page_folio(p)       (_Generic((p),              \
    const struct page *:    (const struct folio *)_compound_head(p), \
    struct page *:      (struct folio *)_compound_head(p)))

/**
 * folio_page - Return a page from a folio.
 * @folio: The folio.
 * @n: The page number to return.
 *
 * @n is relative to the start of the folio.  This function does not
 * check that the page number lies within @folio; the caller is presumed
 * to have a reference to the page.
 */
#define folio_page(folio, n)    nth_page(&(folio)->page, n)

#define PAGE_POISON_PATTERN -1l
static inline int PagePoisoned(const struct page *page)
{
    return READ_ONCE(page->flags) == PAGE_POISON_PATTERN;
}

static __always_inline int PageTail(struct page *page)
{
    return READ_ONCE(page->compound_head) & 1;
}

static __always_inline int PageCompound(struct page *page)
{
    return test_bit(PG_head, &page->flags) || PageTail(page);
}

/*
 * Page flags policies wrt compound pages
 *
 * PF_POISONED_CHECK
 *     check if this struct page poisoned/uninitialized
 *
 * PF_ANY:
 *     the page flag is relevant for small, head and tail pages.
 *
 * PF_HEAD:
 *     for compound page all operations related to the page flag applied to
 *     head page.
 *
 * PF_ONLY_HEAD:
 *     for compound page, callers only ever operate on the head page.
 *
 * PF_NO_TAIL:
 *     modifications of the page flag must be done on small or head pages,
 *     checks can be done on tail pages too.
 *
 * PF_NO_COMPOUND:
 *     the page flag is not relevant for compound pages.
 *
 * PF_SECOND:
 *     the page flag is stored in the first tail page.
 */
#define PF_POISONED_CHECK(page) ({                  \
    VM_BUG_ON_PGFLAGS(PagePoisoned(page), page);    \
    page; })
#define PF_ANY(page, enforce)   PF_POISONED_CHECK(page)
#define PF_HEAD(page, enforce)  PF_POISONED_CHECK(compound_head(page))
#define PF_ONLY_HEAD(page, enforce) ({              \
        VM_BUG_ON_PGFLAGS(PageTail(page), page);    \
        PF_POISONED_CHECK(page); })
#define PF_NO_TAIL(page, enforce) ({                    \
    VM_BUG_ON_PGFLAGS(enforce && PageTail(page), page); \
    PF_POISONED_CHECK(compound_head(page)); })
#define PF_NO_COMPOUND(page, enforce) ({                    \
    VM_BUG_ON_PGFLAGS(enforce && PageCompound(page), page); \
    PF_POISONED_CHECK(page); })

/* Which page is the flag stored in */
#define FOLIO_PF_ANY        0
#define FOLIO_PF_HEAD       0
#define FOLIO_PF_ONLY_HEAD  0
#define FOLIO_PF_NO_TAIL    0
#define FOLIO_PF_NO_COMPOUND    0
#define FOLIO_PF_SECOND     1

static unsigned long *folio_flags(struct folio *folio, unsigned n)
{
    struct page *page = &folio->page;

    VM_BUG_ON_PGFLAGS(PageTail(page), page);
    VM_BUG_ON_PGFLAGS(n > 0 && !test_bit(PG_head, &page->flags), page);
    return &page[n].flags;
}

/*
 * Macros to create function definitions for page flags
 */
#define TESTPAGEFLAG(uname, lname, policy)                              \
static __always_inline bool folio_test_##lname(struct folio *folio)     \
{ return test_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }    \
static __always_inline int Page##uname(struct page *page)               \
{ return test_bit(PG_##lname, &policy(page, 0)->flags); }

#define SETPAGEFLAG(uname, lname, policy)                       \
static __always_inline                                          \
void folio_set_##lname(struct folio *folio)                     \
{ set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }    \
static __always_inline void SetPage##uname(struct page *page)   \
{ set_bit(PG_##lname, &policy(page, 1)->flags); }

#define CLEARPAGEFLAG(uname, lname, policy)                     \
static __always_inline                          \
void folio_clear_##lname(struct folio *folio)               \
{ clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }      \
static __always_inline void ClearPage##uname(struct page *page) \
{ clear_bit(PG_##lname, &policy(page, 1)->flags); }

#define __SETPAGEFLAG(uname, lname, policy)                     \
static __always_inline                                          \
void __folio_set_##lname(struct folio *folio)                   \
{ __set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }  \
static __always_inline void __SetPage##uname(struct page *page) \
{ __set_bit(PG_##lname, &policy(page, 1)->flags); }

#define __CLEARPAGEFLAG(uname, lname, policy)                       \
static __always_inline                                              \
void __folio_clear_##lname(struct folio *folio)                     \
{ __clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); }    \
static __always_inline void __ClearPage##uname(struct page *page)   \
{ __clear_bit(PG_##lname, &policy(page, 1)->flags); }

#define TESTSETFLAG(uname, lname, policy)               \
static __always_inline                          \
bool folio_test_set_##lname(struct folio *folio)            \
{ return test_and_set_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); } \
static __always_inline int TestSetPage##uname(struct page *page)    \
{ return test_and_set_bit(PG_##lname, &policy(page, 1)->flags); }

#define TESTCLEARFLAG(uname, lname, policy)             \
static __always_inline                          \
bool folio_test_clear_##lname(struct folio *folio)          \
{ return test_and_clear_bit(PG_##lname, folio_flags(folio, FOLIO_##policy)); } \
static __always_inline int TestClearPage##uname(struct page *page)  \
{ return test_and_clear_bit(PG_##lname, &policy(page, 1)->flags); }

#define PAGEFLAG(uname, lname, policy)  \
    TESTPAGEFLAG(uname, lname, policy)  \
    SETPAGEFLAG(uname, lname, policy)   \
    CLEARPAGEFLAG(uname, lname, policy)

#define __PAGEFLAG(uname, lname, policy)    \
    TESTPAGEFLAG(uname, lname, policy)      \
    __SETPAGEFLAG(uname, lname, policy)     \
    __CLEARPAGEFLAG(uname, lname, policy)

#define TESTSCFLAG(uname, lname, policy)    \
    TESTSETFLAG(uname, lname, policy)       \
    TESTCLEARFLAG(uname, lname, policy)

#define TESTPAGEFLAG_FALSE(uname, lname) \
    static inline int Page##uname(const struct page *page) { return 0; }

#define SETPAGEFLAG_NOOP(uname, lname) \
    static inline void SetPage##uname(struct page *page) {  }

#define CLEARPAGEFLAG_NOOP(uname, lname) \
    static inline void ClearPage##uname(struct page *page) {  }

#define PAGEFLAG_FALSE(uname, lname)    \
    TESTPAGEFLAG_FALSE(uname, lname)    \
    SETPAGEFLAG_NOOP(uname, lname)      \
    CLEARPAGEFLAG_NOOP(uname, lname)

__PAGEFLAG(Locked, locked, PF_NO_TAIL)
PAGEFLAG(Waiters, waiters, PF_ONLY_HEAD)
PAGEFLAG(Error, error, PF_NO_TAIL) TESTCLEARFLAG(Error, error, PF_NO_TAIL)

PAGEFLAG(Referenced, referenced, PF_HEAD)
    TESTCLEARFLAG(Referenced, referenced, PF_HEAD)
    __SETPAGEFLAG(Referenced, referenced, PF_HEAD)

PAGEFLAG(Dirty, dirty, PF_HEAD)
    TESTSCFLAG(Dirty, dirty, PF_HEAD)
    __CLEARPAGEFLAG(Dirty, dirty, PF_HEAD)

PAGEFLAG(LRU, lru, PF_HEAD)
    __CLEARPAGEFLAG(LRU, lru, PF_HEAD)
    TESTCLEARFLAG(LRU, lru, PF_HEAD)

PAGEFLAG(Active, active, PF_HEAD)
    __CLEARPAGEFLAG(Active, active, PF_HEAD)
    TESTCLEARFLAG(Active, active, PF_HEAD)

PAGEFLAG(Workingset, workingset, PF_HEAD)
    TESTCLEARFLAG(Workingset, workingset, PF_HEAD)

PAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __CLEARPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __SETPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)

PAGEFLAG(SwapBacked, swapbacked, PF_NO_TAIL)
    __CLEARPAGEFLAG(SwapBacked, swapbacked, PF_NO_TAIL)
    __SETPAGEFLAG(SwapBacked, swapbacked, PF_NO_TAIL)

/*
 * Private page markings that may be used by the filesystem that owns the page
 * for its own purposes.
 * - PG_private and PG_private_2 cause releasepage() and co to be invoked
 */
PAGEFLAG(Private, private, PF_ANY)

PAGEFLAG(MappedToDisk, mappedtodisk, PF_NO_TAIL)

PAGEFLAG_FALSE(HighMem, highmem)

PAGEFLAG_FALSE(HWPoison, hwpoison)
#define __PG_HWPOISON 0

static inline void page_init_poison(struct page *page, size_t size)
{
}

__PAGEFLAG(Slab, slab, PF_NO_TAIL)
__PAGEFLAG(Head, head, PF_ANY) CLEARPAGEFLAG(Head, head, PF_ANY)

PAGEFLAG(Unevictable, unevictable, PF_HEAD)
    __CLEARPAGEFLAG(Unevictable, unevictable, PF_HEAD)
    TESTCLEARFLAG(Unevictable, unevictable, PF_HEAD)

#define PAGE_TYPE_BASE  0xf0000000
/* Reserve      0x0000007f to catch underflows of page_mapcount */
#define PAGE_MAPCOUNT_RESERVE   -128
#define PG_buddy    0x00000080
#define PG_offline  0x00000100
#define PG_table    0x00000200
#define PG_guard    0x00000400

#define PageType(page, flag) \
    ((page->page_type & (PAGE_TYPE_BASE | flag)) == PAGE_TYPE_BASE)

static inline int page_has_type(struct page *page)
{
    return (int)page->page_type < PAGE_MAPCOUNT_RESERVE;
}

#define PAGE_TYPE_OPS(uname, lname)                 \
static __always_inline int Page##uname(struct page *page)       \
{                                   \
    return PageType(page, PG_##lname);              \
}                                   \
static __always_inline void __SetPage##uname(struct page *page)     \
{                                   \
    VM_BUG_ON_PAGE(!PageType(page, 0), page);           \
    page->page_type &= ~PG_##lname;                 \
}                                   \
static __always_inline void __ClearPage##uname(struct page *page)   \
{                                   \
    VM_BUG_ON_PAGE(!Page##uname(page), page);           \
    page->page_type |= PG_##lname;                  \
}

/*
 * Marks pages in use as page tables.
 */
PAGE_TYPE_OPS(Table, table)

/*
 * PageBuddy() indicates that the page is free and in the buddy system
 * (see mm/page_alloc.c).
 */
PAGE_TYPE_OPS(Buddy, buddy)

/*
 * Flags checked when a page is prepped for return by the page allocator.
 * Pages being prepped should not have these flags set.  If they are set,
 * there has been a kernel bug or struct page corruption.
 *
 * __PG_HWPOISON is exceptional because it needs to be kept beyond page's
 * alloc-free cycle to prevent from reusing the page.
 */
#define PAGE_FLAGS_CHECK_AT_PREP (PAGEFLAGS_MASK & ~__PG_HWPOISON)

static __always_inline void
set_compound_head(struct page *page, struct page *head)
{
    WRITE_ONCE(page->compound_head, (unsigned long)head + 1);
}

/*
 * On an anonymous page mapped into a user virtual memory area,
 * page->mapping points to its anon_vma, not to a struct address_space;
 * with the PAGE_MAPPING_ANON bit set to distinguish it.  See rmap.h.
 *
 * On an anonymous page in a VM_MERGEABLE area, if CONFIG_KSM is enabled,
 * the PAGE_MAPPING_MOVABLE bit may be set along with the PAGE_MAPPING_ANON
 * bit; and then page->mapping points, not to an anon_vma, but to a private
 * structure which KSM associates with that merged page.  See ksm.h.
 *
 * PAGE_MAPPING_KSM without PAGE_MAPPING_ANON is used for non-lru movable
 * page and then page->mapping points a struct address_space.
 *
 * Please note that, confusingly, "page_mapping" refers to the inode
 * address_space which maps the page from disk; whereas "page_mapped"
 * refers to user virtual address space into which the page is mapped.
 */
#define PAGE_MAPPING_ANON       0x1
#define PAGE_MAPPING_MOVABLE    0x2
#define PAGE_MAPPING_KSM        (PAGE_MAPPING_ANON | PAGE_MAPPING_MOVABLE)
#define PAGE_MAPPING_FLAGS      (PAGE_MAPPING_ANON | PAGE_MAPPING_MOVABLE)

static __always_inline int __PageMovable(struct page *page)
{
    return ((unsigned long)page->mapping & PAGE_MAPPING_FLAGS) ==
        PAGE_MAPPING_MOVABLE;
}

#define __PG_MLOCKED    (1UL << PG_mlocked)

/*
 * Flags checked when a page is freed.  Pages being freed should not have
 * these flags set.  If they are, there is a problem.
 */
#define PAGE_FLAGS_CHECK_AT_FREE                \
    (1UL << PG_lru      | 1UL << PG_locked  |   \
     1UL << PG_private  | 1UL << PG_private_2   |   \
     1UL << PG_writeback| 1UL << PG_reserved    |   \
     1UL << PG_slab     | 1UL << PG_active  |   \
     1UL << PG_unevictable  | __PG_MLOCKED)

/*
 * A version of PageSlabPfmemalloc() for opportunistic checks where the page
 * might have been freed under us and not be a PageSlab anymore.
 */
static inline int __PageSlabPfmemalloc(struct page *page)
{
    return PageActive(page);
}

static inline void SetPageSlabPfmemalloc(struct page *page)
{
    VM_BUG_ON_PAGE(!PageSlab(page), page);
    SetPageActive(page);
}

static inline void __ClearPageSlabPfmemalloc(struct page *page)
{
    VM_BUG_ON_PAGE(!PageSlab(page), page);
    __ClearPageActive(page);
}

static inline void ClearPageSlabPfmemalloc(struct page *page)
{
    VM_BUG_ON_PAGE(!PageSlab(page), page);
    ClearPageActive(page);
}

#define PG_head_mask ((1UL << PG_head))

int PageHuge(struct page *page);
int PageHeadHuge(struct page *page);
static inline bool folio_test_hugetlb(struct folio *folio)
{
    return PageHeadHuge(&folio->page);
}

/**
 * folio_test_uptodate - Is this folio up to date?
 * @folio: The folio.
 *
 * The uptodate flag is set on a folio when every byte in the folio is
 * at least as new as the corresponding bytes on storage.  Anonymous
 * and CoW folios are always uptodate.  If the folio is not uptodate,
 * some of the bytes in it may be; see the is_partially_uptodate()
 * address_space operation.
 */
static inline bool folio_test_uptodate(struct folio *folio)
{
    bool ret = test_bit(PG_uptodate, folio_flags(folio, 0));
    /*
     * Must ensure that the data we read out of the folio is loaded
     * _after_ we've loaded folio->flags to check the uptodate bit.
     * We can skip the barrier if the folio is not uptodate, because
     * we wouldn't be reading anything from it.
     *
     * See folio_mark_uptodate() for the other side of the story.
     */
    if (ret)
        smp_rmb();

    return ret;
}

static __always_inline void folio_mark_uptodate(struct folio *folio)
{
    /*
     * Memory barrier must be issued before setting the PG_uptodate bit,
     * so that all previous stores issued in order to bring the folio
     * uptodate are actually visible before folio_test_uptodate becomes true.
     */
    smp_wmb();
    set_bit(PG_uptodate, folio_flags(folio, 0));
}

static __always_inline void SetPageUptodate(struct page *page)
{
    folio_mark_uptodate((struct folio *)page);
}

static inline int PageUptodate(struct page *page)
{
    return folio_test_uptodate(page_folio(page));
}

CLEARPAGEFLAG(Uptodate, uptodate, PF_NO_TAIL)

#undef PF_ANY
#undef PF_HEAD
#undef PF_ONLY_HEAD
#undef PF_NO_TAIL
#undef PF_NO_COMPOUND
#undef PF_SECOND

#endif /* !__GENERATING_BOUNDS_H */

#endif  /* PAGE_FLAGS_H */
