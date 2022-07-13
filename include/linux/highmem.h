/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HIGHMEM_H
#define _LINUX_HIGHMEM_H

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/bug.h>
//#include <linux/cacheflush.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/string.h>
//#include <linux/hardirq.h>

#include "highmem-internal.h"

static inline void clear_highpage(struct page *page)
{
    void *kaddr = kmap_local_page(page);
    clear_page(kaddr);
    kunmap_local(kaddr);
}

#endif /* _LINUX_HIGHMEM_H */
