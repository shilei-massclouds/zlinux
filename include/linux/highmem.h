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

#endif /* _LINUX_HIGHMEM_H */
