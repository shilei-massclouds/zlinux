/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_PAGE_H
#define _ASM_RISCV_PAGE_H

#include <linux/pfn.h>
#include <linux/const.h>

#define PAGE_SHIFT  (12)
#define PAGE_SIZE   (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK   (~(PAGE_SIZE - 1))

#define PAGE_OFFSET kernel_map.page_offset

/*
 * By default, CONFIG_PAGE_OFFSET value corresponds to SV48 address space so
 * define the PAGE_OFFSET value for SV39.
 */
#define PAGE_OFFSET_L4  _AC(0xffffaf8000000000, UL)
#define PAGE_OFFSET_L3  _AC(0xffffffd800000000, UL)

#define PTE_FMT "%016lx"

#ifndef __ASSEMBLY__

#define clear_page(pgaddr)  memset((pgaddr), 0, PAGE_SIZE)
#define copy_page(to, from) memcpy((to), (from), PAGE_SIZE)

#define clear_user_page(pgaddr, vaddr, page) memset((pgaddr), 0, PAGE_SIZE)

#define copy_user_page(vto, vfrom, vaddr, topg) \
    memcpy((vto), (vfrom), PAGE_SIZE)

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

#define linear_mapping_pa_to_va(x) \
    ((void *)((unsigned long)(x) + kernel_map.va_pa_offset))

#define kernel_mapping_pa_to_va(y)  ({                              \
    unsigned long _y = y;                                           \
    (void *)((unsigned long)(_y) + kernel_map.va_kernel_pa_offset); \
})

#define __pa_to_va_nodebug(x) linear_mapping_pa_to_va(x)

#define is_linear_mapping(x) \
    ((x) >= PAGE_OFFSET && (x) < kernel_map.virt_addr)

#define linear_mapping_va_to_pa(x) \
    ((unsigned long)(x) - kernel_map.va_pa_offset)

#define kernel_mapping_va_to_pa(y) ({ \
    unsigned long _y = y; \
    ((unsigned long)(_y) - kernel_map.va_kernel_pa_offset); \
})

#define __va_to_pa_nodebug(x) ({                    \
    unsigned long _x = x;                           \
    is_linear_mapping(_x) ?                         \
        linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_x);  \
})

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

#define phys_to_pfn(phys)   (PFN_DOWN(phys))
#define pfn_to_phys(pfn)    (PFN_PHYS(pfn))

#define virt_to_pfn(vaddr)  (phys_to_pfn(__pa(vaddr)))
#define pfn_to_virt(pfn)    (__va(pfn_to_phys(pfn)))

#define virt_to_page(vaddr) (pfn_to_page(virt_to_pfn(vaddr)))
#define page_to_virt(page)  (pfn_to_virt(page_to_pfn(page)))

#define page_to_phys(page)  (pfn_to_phys(page_to_pfn(page)))

#define sym_to_pfn(x)       __phys_to_pfn(__pa_symbol(x))

#define pfn_valid(pfn) \
    (((pfn) >= ARCH_PFN_OFFSET) && (((pfn) - ARCH_PFN_OFFSET) < max_mapnr))

#endif /* !__ASSEMBLY__ */

#define virt_addr_valid(vaddr) ({ \
    unsigned long _addr = (unsigned long)vaddr; \
    (unsigned long)(_addr) >= PAGE_OFFSET && pfn_valid(virt_to_pfn(_addr)); \
})

#define VM_DATA_DEFAULT_FLAGS   VM_DATA_FLAGS_NON_EXEC

#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>

#endif /* _ASM_RISCV_PAGE_H */
