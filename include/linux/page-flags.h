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
    PG_reserved,
    PG_head,        /* A head page */

    __NR_PAGEFLAGS,
};

#ifndef __GENERATING_BOUNDS_H

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

PAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __CLEARPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)
    __SETPAGEFLAG(Reserved, reserved, PF_NO_COMPOUND)

PAGEFLAG_FALSE(HWPoison, hwpoison)

static inline void page_init_poison(struct page *page, size_t size)
{
}

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

#endif /* !__GENERATING_BOUNDS_H */

#endif  /* PAGE_FLAGS_H */
