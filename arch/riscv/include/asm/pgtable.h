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
#include <asm/tlbflush.h>
#include <linux/mm_types.h>

#include <asm/pgtable-64.h>

/* Number of entries in the page global directory */
#define PTRS_PER_PGD    (PAGE_SIZE / sizeof(pgd_t))
/* Number of entries in the page table */
#define PTRS_PER_PTE    (PAGE_SIZE / sizeof(pte_t))

/* Number of PGD entries that a user-mode program can use */
#define USER_PTRS_PER_PGD   (TASK_SIZE / PGDIR_SIZE)

/* Page protection bits */
#define _PAGE_BASE  (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_USER)

#define PAGE_NONE       __pgprot(_PAGE_PROT_NONE | _PAGE_READ)
#define PAGE_READ       __pgprot(_PAGE_BASE | _PAGE_READ)
#define PAGE_WRITE      __pgprot(_PAGE_BASE | _PAGE_READ | _PAGE_WRITE)
#define PAGE_EXEC       __pgprot(_PAGE_BASE | _PAGE_EXEC)
#define PAGE_READ_EXEC  __pgprot(_PAGE_BASE | _PAGE_READ | _PAGE_EXEC)
#define PAGE_WRITE_EXEC __pgprot(_PAGE_BASE | _PAGE_READ | \
                                 _PAGE_EXEC | _PAGE_WRITE)

#define PAGE_COPY           PAGE_READ
#define PAGE_COPY_EXEC      PAGE_EXEC
#define PAGE_COPY_READ_EXEC PAGE_READ_EXEC
#define PAGE_SHARED         PAGE_WRITE
#define PAGE_SHARED_EXEC    PAGE_WRITE_EXEC

#define _PAGE_KERNEL    (_PAGE_READ | _PAGE_WRITE | _PAGE_PRESENT | \
                         _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_KERNEL         __pgprot(_PAGE_KERNEL)
#define PAGE_KERNEL_READ    __pgprot(_PAGE_KERNEL & ~_PAGE_WRITE)
#define PAGE_KERNEL_EXEC    __pgprot(_PAGE_KERNEL | _PAGE_EXEC)
#define PAGE_KERNEL_READ_EXEC \
    __pgprot((_PAGE_KERNEL & ~_PAGE_WRITE) | _PAGE_EXEC)

#define PAGE_TABLE          __pgprot(_PAGE_TABLE)

/*
 * The RISC-V ISA doesn't yet specify how to query or modify PMAs, so we can't
 * change the properties of memory regions.
 */
#define _PAGE_IOREMAP   _PAGE_KERNEL

/* MAP_PRIVATE permissions: xwr (copy-on-write) */
#define __P000  PAGE_NONE
#define __P001  PAGE_READ
#define __P010  PAGE_COPY
#define __P011  PAGE_COPY
#define __P100  PAGE_EXEC
#define __P101  PAGE_READ_EXEC
#define __P110  PAGE_COPY_EXEC
#define __P111  PAGE_COPY_READ_EXEC

/* MAP_SHARED permissions: xwr */
#define __S000  PAGE_NONE
#define __S001  PAGE_READ
#define __S010  PAGE_SHARED
#define __S011  PAGE_SHARED
#define __S100  PAGE_EXEC
#define __S101  PAGE_READ_EXEC
#define __S110  PAGE_SHARED_EXEC
#define __S111  PAGE_SHARED_EXEC

#define TASK_SIZE       (PGDIR_SIZE * PTRS_PER_PGD / 2)
#define TASK_SIZE_MIN   (PGDIR_SIZE_L3 * PTRS_PER_PGD / 2)

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

#define mk_pte(page, prot)  pfn_pte(page_to_pfn(page), prot)

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

void paging_init(void);
void misc_mem_init(void);

#define pgd_ERROR(e) \
    pr_err("%s:%d: bad pgd " PTE_FMT ".\n", __FILE__, __LINE__, pgd_val(e))

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
                                       unsigned long address, pte_t *ptep)
{
    return __pte(atomic_long_xchg((atomic_long_t *)ptep, 0));
}

static inline int pmd_none(pmd_t pmd)
{
    return (pmd_val(pmd) == 0);
}

static inline int pmd_present(pmd_t pmd)
{
    return (pmd_val(pmd) & (_PAGE_PRESENT | _PAGE_PROT_NONE));
}

static inline int pmd_bad(pmd_t pmd)
{
    return !pmd_present(pmd) || (pmd_val(pmd) & _PAGE_LEAF);
}

static inline void set_pmd(pmd_t *pmdp, pmd_t pmd)
{
    *pmdp = pmd;
}

static inline void pmd_clear(pmd_t *pmdp)
{
    set_pmd(pmdp, __pmd(0));
}

static inline pte_t pte_mkhuge(pte_t pte)
{
    return pte;
}

/* Yields the page frame number (PFN) of a page table entry */
static inline unsigned long pte_pfn(pte_t pte)
{
    return (pte_val(pte) >> _PAGE_PFN_SHIFT);
}

#define pte_page(x)     pfn_to_page(pte_pfn(x))

/* Commit new configuration to MMU hardware */
static inline void update_mmu_cache(struct vm_area_struct *vma,
                                    unsigned long address, pte_t *ptep)
{
    /*
     * The kernel assumes that TLBs don't cache invalid entries, but
     * in RISC-V, SFENCE.VMA specifies an ordering constraint, not a
     * cache flush; it is necessary even after writing invalid entries.
     * Relying on flush_tlb_fix_spurious_fault would suffice, but
     * the extra traps reduce performance.  So, eagerly SFENCE.VMA.
     */
    local_flush_tlb_page(address);
}

/* static inline pte_t pte_mkread(pte_t pte) */

static inline pte_t pte_mkwrite(pte_t pte)
{
    return __pte(pte_val(pte) | _PAGE_WRITE);
}

/* static inline pte_t pte_mkexec(pte_t pte) */

static inline pte_t pte_mkdirty(pte_t pte)
{
    return __pte(pte_val(pte) | _PAGE_DIRTY);
}

static inline pte_t pte_mkclean(pte_t pte)
{
    return __pte(pte_val(pte) & ~(_PAGE_DIRTY));
}

static inline pte_t pte_mkyoung(pte_t pte)
{
    return __pte(pte_val(pte) | _PAGE_ACCESSED);
}

static inline pte_t pte_mkold(pte_t pte)
{
    return __pte(pte_val(pte) & ~(_PAGE_ACCESSED));
}

static inline pte_t pte_mkspecial(pte_t pte)
{
    return __pte(pte_val(pte) | _PAGE_SPECIAL);
}

static inline struct page *pmd_page(pmd_t pmd)
{
    return pfn_to_page(pmd_val(pmd) >> _PAGE_PFN_SHIFT);
}

static inline int pte_dirty(pte_t pte)
{
    return pte_val(pte) & _PAGE_DIRTY;
}

#define pmd_leaf    pmd_leaf
static inline int pmd_leaf(pmd_t pmd)
{
    return pmd_present(pmd) && (pmd_val(pmd) & _PAGE_LEAF);
}

static inline int pte_huge(pte_t pte)
{
    return pte_present(pte) && (pte_val(pte) & _PAGE_LEAF);
}

static inline int pte_young(pte_t pte)
{
    return pte_val(pte) & _PAGE_ACCESSED;
}

static inline int pte_special(pte_t pte)
{
    return pte_val(pte) & _PAGE_SPECIAL;
}

#define __HAVE_ARCH_PTE_SAME
static inline int pte_same(pte_t pte_a, pte_t pte_b)
{
    return pte_val(pte_a) == pte_val(pte_b);
}

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PGTABLE_H */
