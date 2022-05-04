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

extern unsigned long va_pa_offset;
extern unsigned long pfn_base;

extern unsigned long riscv_pfn_base;
#define ARCH_PFN_OFFSET (riscv_pfn_base)

#define pte_val(x)  ((x).pte)
#define pgd_val(x)  ((x).pgd)
#define pgprot_val(x)   ((x).pgprot)

#define __pte(x)    ((pte_t) { (x) })
#define __pgd(x)    ((pgd_t) { (x) })
#define __pgprot(x) ((pgprot_t) { (x) })

#define __va_to_pa_nodebug(x) ((unsigned long)(x) - va_pa_offset)
#define __pa_to_va_nodebug(x) \
    ((void *)((unsigned long) (x) + va_pa_offset))

#define __phys_addr_symbol(x) __va_to_pa_nodebug(x)

#define __virt_to_phys(x)       __va_to_pa_nodebug(x)
#define __phys_addr_symbol(x)   __va_to_pa_nodebug(x)

#define __pa_symbol(x) \
    __phys_addr_symbol(RELOC_HIDE((unsigned long)(x), 0))

#define __pa(x) __virt_to_phys((unsigned long)(x))
#define __va(x) ((void *)__pa_to_va_nodebug((phys_addr_t)(x)))

struct kernel_mapping {
    unsigned long page_offset;
    unsigned long virt_addr;
    uintptr_t phys_addr;
    uintptr_t size;
    /* Offset between linear mapping virtual address and kernel load address */
    unsigned long va_pa_offset;
    /* Offset between kernel mapping virtual address and kernel load address */
    unsigned long va_kernel_pa_offset;
    unsigned long va_kernel_xip_pa_offset;
};

extern struct kernel_mapping kernel_map;
extern phys_addr_t phys_ram_base;

#endif /* !__ASSEMBLY__ */

#include <asm-generic/memory_model.h>
//#include <asm-generic/getorder.h>

#endif /* _ASM_RISCV_PAGE_H */
