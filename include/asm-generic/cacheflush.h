/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_CACHEFLUSH_H
#define _ASM_GENERIC_CACHEFLUSH_H

struct mm_struct;
struct vm_area_struct;
struct page;
struct address_space;

#ifndef flush_cache_page
static inline void flush_cache_page(struct vm_area_struct *vma,
                    unsigned long vmaddr,
                    unsigned long pfn)
{
}
#endif

#ifndef flush_icache_page
static inline void flush_icache_page(struct vm_area_struct *vma,
                                     struct page *page)
{
}
#endif

#endif /* _ASM_GENERIC_CACHEFLUSH_H */
