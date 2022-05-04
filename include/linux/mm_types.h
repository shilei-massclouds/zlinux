/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/log2.h>

#define _struct_page_alignment

struct page {
    unsigned long flags;    /* Atomic flags, some possibly updated asynchronously */

} _struct_page_alignment;

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT   (order_base_2(sizeof(struct page)))

struct mm_struct {
};

extern struct mm_struct init_mm;

#endif /* _LINUX_MM_TYPES_H */
