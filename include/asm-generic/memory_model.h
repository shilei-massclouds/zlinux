/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MEMORY_MODEL_H
#define __ASM_MEMORY_MODEL_H

#include <linux/pfn.h>

#ifndef __ASSEMBLY__

#ifndef ARCH_PFN_OFFSET
#define ARCH_PFN_OFFSET     (0UL)
#endif

#define __pfn_to_page(pfn)  (mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define __page_to_pfn(page) \
    ((unsigned long)((page) - mem_map) + ARCH_PFN_OFFSET)

/*
 * Convert a physical address to a Page Frame Number and back
 */
#define __phys_to_pfn(paddr)    PHYS_PFN(paddr)
#define __pfn_to_phys(pfn)      PFN_PHYS(pfn)

#define page_to_pfn __page_to_pfn
#define pfn_to_page __pfn_to_page

#endif /* __ASSEMBLY__ */

#endif /* __ASM_MEMORY_MODEL_H */
