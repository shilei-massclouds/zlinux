/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGE_MM_H
#define _LINUX_HUGE_MM_H

#include <linux/sched/coredump.h>
#include <linux/mm_types.h>

#include <linux/fs.h> /* only for vma_is_dax() */

#define transparent_hugepage_flags 0UL

#define thp_get_unmapped_area   NULL

#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)

#define HPAGE_PMD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })

#define HPAGE_PUD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SIZE ({ BUILD_BUG(); 0; })

static inline int is_swap_pmd(pmd_t pmd)
{
    return 0;
}

static inline bool folio_test_pmd_mappable(struct folio *folio)
{
    return false;
}

#endif /* _LINUX_HUGE_MM_H */
