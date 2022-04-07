/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_PAGE_H
#define _ASM_RISCV_PAGE_H

#include <linux/const.h>

#define PAGE_SHIFT  (12)
#define PAGE_SIZE   (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK   (~(PAGE_SIZE - 1))

#define PAGE_OFFSET _AC(CONFIG_PAGE_OFFSET, UL)

#define KERN_VIRT_SIZE (-PAGE_OFFSET)

#ifndef __ASSEMBLY__

/*
 * Use struct definitions to apply C type checking
 */

/* Page Global Directory entry */
typedef struct {
    unsigned long pgd;
} pgd_t;

/* Page Table entry */
typedef struct {
    unsigned long pte;
} pte_t;

typedef struct {
    unsigned long pgprot;
} pgprot_t;

typedef struct page *pgtable_t;

#define pte_val(x)  ((x).pte)
#define pgd_val(x)  ((x).pgd)
#define pgprot_val(x)   ((x).pgprot)

#define __pte(x)    ((pte_t) { (x) })
#define __pgd(x)    ((pgd_t) { (x) })
#define __pgprot(x) ((pgprot_t) { (x) })

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_PAGE_H */
