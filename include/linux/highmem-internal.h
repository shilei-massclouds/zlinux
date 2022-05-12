/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HIGHMEM_INTERNAL_H
#define _LINUX_HIGHMEM_INTERNAL_H

static inline void *kmap_local_page(struct page *page)
{
    return page_address(page);
}

static inline void __kunmap_local(void *addr)
{
}

#define kunmap_local(__addr)                    \
do {                                \
    BUILD_BUG_ON(__same_type((__addr), struct page *)); \
    __kunmap_local(__addr);                 \
} while (0)

#endif /* _LINUX_HIGHMEM_INTERNAL_H */
