/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Macros for manipulating and testing page->flags
 */

#ifndef PAGE_FLAGS_H
#define PAGE_FLAGS_H

#include <linux/types.h>
#include <linux/bug.h>
//#include <linux/mmdebug.h>
#ifndef __GENERATING_BOUNDS_H
#include <linux/mm_types.h>
#include <generated/bounds.h>
#endif /* !__GENERATING_BOUNDS_H */

#ifndef __GENERATING_BOUNDS_H

static inline void page_init_poison(struct page *page, size_t size)
{
}

#endif /* !__GENERATING_BOUNDS_H */

#endif  /* PAGE_FLAGS_H */
