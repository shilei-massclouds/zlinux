/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PGTABLE_H
#define _ASM_RISCV_PGTABLE_H

#include <linux/mmzone.h>
#include <linux/sizes.h>

#include <asm/pgtable-bits.h>

#define ADDRESS_SPACE_END   (UL(-1))

/* Leave 2GB for kernel and BPF at the end of the address space */
#define KERNEL_LINK_ADDR    (ADDRESS_SPACE_END - SZ_2G + 1)

/*
 * Half of the kernel address space (half of the entries of the page global
 * directory) is for the direct mapping.
 */
#define KERN_VIRT_SIZE  ((PTRS_PER_PGD / 2 * PGDIR_SIZE) / 2)

#define VMALLOC_SIZE    (KERN_VIRT_SIZE >> 1)
#define VMALLOC_END     PAGE_OFFSET
#define VMALLOC_START   (PAGE_OFFSET - VMALLOC_SIZE)

/*
 * Roughly size the vmemmap space to be large enough to fit enough
 * struct pages to map half the virtual address space. Then
 * position vmemmap directly below the VMALLOC region.
 */
#define VA_BITS 57

/*
 * Roughly size the vmemmap space to be large enough to fit enough
 * struct pages to map half the virtual address space. Then
 * position vmemmap directly below the VMALLOC region.
 */
#define VMEMMAP_SHIFT \
    (VA_BITS - PAGE_SHIFT - 1 + STRUCT_PAGE_MAX_SHIFT)
#define VMEMMAP_SIZE    BIT(VMEMMAP_SHIFT)
#define VMEMMAP_END     VMALLOC_START
#define VMEMMAP_START   (VMALLOC_START - VMEMMAP_SIZE)

#define PCI_IO_SIZE     SZ_16M
#define PCI_IO_END      VMEMMAP_START
#define PCI_IO_START    (PCI_IO_END - PCI_IO_SIZE)

#define FIXADDR_TOP     PCI_IO_START
#define FIXADDR_SIZE    PMD_SIZE
#define FIXADDR_START   (FIXADDR_TOP - FIXADDR_SIZE)

#ifndef __ASSEMBLY__

#include <asm/page.h>
#include <linux/mm_types.h>

#include <asm/pgtable-64.h>

/* Number of entries in the page global directory */
#define PTRS_PER_PGD    (PAGE_SIZE / sizeof(pgd_t))
/* Number of entries in the page table */
#define PTRS_PER_PTE    (PAGE_SIZE / sizeof(pte_t))

#define _PAGE_KERNEL    (_PAGE_READ | _PAGE_WRITE | _PAGE_PRESENT | \
                         _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_KERNEL         __pgprot(_PAGE_KERNEL)
#define PAGE_KERNEL_READ    __pgprot(_PAGE_KERNEL & ~_PAGE_WRITE)
#define PAGE_KERNEL_EXEC    __pgprot(_PAGE_KERNEL | _PAGE_EXEC)
#define PAGE_KERNEL_READ_EXEC \
    __pgprot((_PAGE_KERNEL & ~_PAGE_WRITE) | _PAGE_EXEC)

#define PAGE_TABLE          __pgprot(_PAGE_TABLE)

struct pt_alloc_ops {
    pte_t *(*get_pte_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_pte)(uintptr_t va);
    pmd_t *(*get_pmd_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_pmd)(uintptr_t va);
    pud_t *(*get_pud_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_pud)(uintptr_t va);
    p4d_t *(*get_p4d_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_p4d)(uintptr_t va);
};

static inline int pmd_none(pmd_t pmd)
{
    return (pmd_val(pmd) == 0);
}

static inline pgd_t pfn_pgd(unsigned long pfn, pgprot_t prot)
{
    return __pgd((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _pgd_pfn(pgd_t pgd)
{
    return pgd_val(pgd) >> _PAGE_PFN_SHIFT;
}

/* Constructs a page table entry */
static inline pte_t pfn_pte(unsigned long pfn, pgprot_t prot)
{
    return __pte((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline int pte_present(pte_t pte)
{
    return (pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROT_NONE));
}

static inline int pte_none(pte_t pte)
{
    return (pte_val(pte) == 0);
}

static inline int pte_write(pte_t pte)
{
    return pte_val(pte) & _PAGE_WRITE;
}

static inline int pte_exec(pte_t pte)
{
    return pte_val(pte) & _PAGE_EXEC;
}

/*
 * Certain architectures need to do special things when PTEs within
 * a page table are directly modified.  Thus, the following hook is
 * made available.
 */
static inline void set_pte(pte_t *ptep, pte_t pteval)
{
    *ptep = pteval;
}

void flush_icache_pte(pte_t pte);

static inline void
set_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep, pte_t pteval)
{
    if (pte_present(pteval) && pte_exec(pteval))
        flush_icache_pte(pteval);

    set_pte(ptep, pteval);
}

static inline void
pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
    set_pte_at(mm, addr, ptep, __pte(0));
}

extern void *_dtb_early_va;
extern uintptr_t _dtb_early_pa;

#define dtb_early_va    _dtb_early_va
#define dtb_early_pa    _dtb_early_pa

extern pgd_t swapper_pg_dir[];

void setup_bootmem(void);
void paging_init(void);
void misc_mem_init(void);

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PGTABLE_H */
