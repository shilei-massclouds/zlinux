/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PGTABLE_H
#define _ASM_RISCV_PGTABLE_H

#include <linux/mmzone.h>
#include <linux/sizes.h>

#include <asm/pgtable-bits.h>

#ifndef __ASSEMBLY__

#include <asm/page.h>
#include <linux/mm_types.h>

#define VMALLOC_SIZE    (KERN_VIRT_SIZE >> 1)
#define VMALLOC_END     (PAGE_OFFSET - 1)
#define VMALLOC_START   (PAGE_OFFSET - VMALLOC_SIZE)

/*
 * Roughly size the vmemmap space to be large enough to fit enough
 * struct pages to map half the virtual address space. Then
 * position vmemmap directly below the VMALLOC region.
 */
#define VMEMMAP_SHIFT \
    (CONFIG_VA_BITS - PAGE_SHIFT - 1 + STRUCT_PAGE_MAX_SHIFT)
#define VMEMMAP_SIZE    BIT(VMEMMAP_SHIFT)
#define VMEMMAP_END     (VMALLOC_START - 1)
#define VMEMMAP_START   (VMALLOC_START - VMEMMAP_SIZE)

#define PCI_IO_SIZE     SZ_16M
#define PCI_IO_END      VMEMMAP_START
#define PCI_IO_START    (PCI_IO_END - PCI_IO_SIZE)

#define FIXADDR_TOP     PCI_IO_START
#define FIXADDR_SIZE    PMD_SIZE
#define FIXADDR_START   (FIXADDR_TOP - FIXADDR_SIZE)

#include <asm/pgtable-64.h>

/* Number of entries in the page global directory */
#define PTRS_PER_PGD    (PAGE_SIZE / sizeof(pgd_t))
/* Number of entries in the page table */
#define PTRS_PER_PTE    (PAGE_SIZE / sizeof(pte_t))

#define _PAGE_KERNEL    (_PAGE_READ | _PAGE_WRITE | _PAGE_PRESENT | \
                         _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_KERNEL_EXEC    __pgprot(_PAGE_KERNEL | _PAGE_EXEC)

#define PAGE_TABLE          __pgprot(_PAGE_TABLE)

static inline int pmd_none(pmd_t pmd)
{
    return (pmd_val(pmd) == 0);
}

static inline pgd_t pfn_pgd(unsigned long pfn, pgprot_t prot)
{
    return __pgd((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PGTABLE_H */
