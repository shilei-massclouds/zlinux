/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HIGHMEM_H
#define _LINUX_HIGHMEM_H

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/cacheflush.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/hardirq.h>

#include "highmem-internal.h"

static inline void clear_highpage(struct page *page)
{
    void *kaddr = kmap_local_page(page);
    clear_page(kaddr);
    kunmap_local(kaddr);
}

static inline void zero_user_segments(struct page *page,
                                      unsigned start1, unsigned end1,
                                      unsigned start2, unsigned end2)
{
    void *kaddr = kmap_local_page(page);
    unsigned int i;

    BUG_ON(end1 > page_size(page) || end2 > page_size(page));

    if (end1 > start1)
        memset(kaddr + start1, 0, end1 - start1);

    if (end2 > start2)
        memset(kaddr + start2, 0, end2 - start2);

    kunmap_local(kaddr);
    for (i = 0; i < compound_nr(page); i++)
        flush_dcache_page(page + i);
}

static inline void zero_user(struct page *page,
                             unsigned start, unsigned size)
{
    zero_user_segments(page, start, start + size, 0, 0);
}

/* when CONFIG_HIGHMEM is not set these will be plain clear/copy_page */
#ifndef clear_user_highpage
static inline void clear_user_highpage(struct page *page, unsigned long vaddr)
{
    void *addr = kmap_local_page(page);
    clear_user_page(addr, vaddr, page);
    kunmap_local(addr);
}
#endif

/**
 * alloc_zeroed_user_highpage_movable - Allocate a zeroed HIGHMEM page for a VMA that the caller knows can move
 * @vma: The VMA the page is to be allocated for
 * @vaddr: The virtual address the page will be inserted into
 *
 * This function will allocate a page for a VMA that the caller knows will
 * be able to migrate in the future using move_pages() or reclaimed
 *
 * An architecture may override this function by defining
 * __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE_MOVABLE and providing their own
 * implementation.
 */
static inline struct page *
alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
                                   unsigned long vaddr)
{
    struct page *page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vaddr);

    if (page)
        clear_user_highpage(page, vaddr);

    return page;
}

static inline void zero_user_segment(struct page *page,
                                     unsigned start, unsigned end)
{
    zero_user_segments(page, start, end, 0, 0);
}

#endif /* _LINUX_HIGHMEM_H */
