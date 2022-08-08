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

static inline unsigned int nr_free_highpages(void) { return 0; }
static inline unsigned long totalhigh_pages(void) { return 0UL; }

static inline void *kmap_atomic(struct page *page)
{
    preempt_disable();
    pagefault_disable();
    return page_address(page);
}

/*
 * Prevent people trying to call kunmap_atomic() as if it were kunmap()
 * kunmap_atomic() should get the return value of kmap_atomic, not the page.
 */
#define kunmap_atomic(__addr)                   \
do {                                \
    BUILD_BUG_ON(__same_type((__addr), struct page *)); \
    __kunmap_atomic(__addr);                \
} while (0)

static inline void __kunmap_atomic(void *addr)
{
    pagefault_enable();
    preempt_enable();
}

#endif /* _LINUX_HIGHMEM_INTERNAL_H */
