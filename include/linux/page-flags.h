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
    PG_lru,
    PG_reserved,
    PG_head,        /* A head page */

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
#define PF_NO_COMPOUND(page, enforce) ({                    \
    VM_BUG_ON_PGFLAGS(enforce && PageCompound(page), page); \
    PF_POISONED_CHECK(page); })

/*
 * Macros to create function definitions for page flags
 */
#define TESTPAGEFLAG(uname, lname, policy)                  \
static __always_inline int Page##uname(struct page *page)   \
{ return test_bit(PG_##lname, &policy(page, 0)->flags); }

#define SETPAGEFLAG(uname, lname, policy)                       \
static __always_inline void SetPage##uname(struct page *page)   \
{ set_bit(PG_##lname, &policy(page, 1)->flags); }

#define CLEARPAGEFLAG(uname, lname, policy)                     \
static __always_inline void ClearPage##uname(struct page *page) \
{ clear_bit(PG_##lname, &policy(page, 1)->flags); }

#define __SETPAGEFLAG(uname, lname, policy)                     \
static __always_inline void __SetPage##uname(struct page *page) \
{ __set_bit(PG_##lname, &policy(page, 1)->flags); }

#define __CLEARPAGEFLAG(uname, lname, policy)               \
static __always_inline void __ClearPage##uname(struct page *page)   \
{ __clear_bit(PG_##lname, &policy(page, 1)->flags); }

#define PAGEFLAG(uname, lname, policy)  \
    TESTPAGEFLAG(uname, lname, policy)  \
    SETPAGEFLAG(uname, lname, policy)   \
    CLEARPAGEFLAG(uname, lname, policy)

#define __PAGEFLAG(uname, lname, policy)    \
    TESTPAGEFLAG(uname, lname, policy)      \
    __SETPAGEFLAG(uname, lname, policy)     \
    __CLEARPAGEFLAG(uname, lname, policy)

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

#define TESTCLEARFLAG(uname, lname, policy) \
static __always_inline int TestClearPage##uname(struct page *page) \
{ return test_and_clear_bit(PG_##lname, &policy(page, 1)->flags); }

PAGEFLAG(LRU, lru, PF_HEAD)
    __CLEARPAGEFLAG(LRU, lru, PF_HEAD)
    TESTCLEARFLAG(LRU, lru, PF_HEAD)

PAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __CLEARPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __SETPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)

PAGEFLAG_FALSE(HWPoison, hwpoison)
#define __PG_HWPOISON 0

static inline void page_init_poison(struct page *page, size_t size)
{
}

__PAGEFLAG(Head, head, PF_ANY) CLEARPAGEFLAG(Head, head, PF_ANY)

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

#endif /* !__GENERATING_BOUNDS_H */

#endif  /* PAGE_FLAGS_H */
