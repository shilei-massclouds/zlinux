/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGTABLE_H
#define _LINUX_PGTABLE_H

#include <linux/pfn.h>
#include <asm/pgtable.h>

#ifndef __ASSEMBLY__

#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
#define pte_unmap(pte) ((void)(pte)) /* NOP */

static inline unsigned long pte_index(unsigned long address)
{
    return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

#ifndef pmd_index
static inline unsigned long pmd_index(unsigned long address)
{
    return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}
#define pmd_index pmd_index
#endif

#ifndef pgd_index
/* Must be a compile-time constant, so implement it as a macro */
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#endif

static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
    return (pgd + pgd_index(address));
};

/*
 * a shortcut to get a pgd_t in a given mm
 */
#ifndef pgd_offset
#define pgd_offset(mm, address) pgd_offset_pgd((mm)->pgd, (address))
#endif

/*
 * a shortcut which implies the use of the kernel's pgd, instead
 * of a process's
 */
#ifndef pgd_offset_k
#define pgd_offset_k(address)   pgd_offset(&init_mm, (address))
#endif

/*
 * When walking page tables, get the address of the next boundary,
 * or the end address of the range if that comes earlier.  Although no
 * vma end wraps to 0, rounded up __boundary may wrap to 0 throughout.
 */

#define pgd_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})

#ifndef p4d_addr_end
#define p4d_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + P4D_SIZE) & P4D_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

#ifndef pud_addr_end
#define pud_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

#ifndef pmd_addr_end
#define pmd_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

/*
 * Page Table Modification bits for pgtbl_mod_mask.
 *
 * These are used by the p?d_alloc_track*() set of functions an in the generic
 * vmalloc/ioremap code to track at which page-table levels entries have been
 * modified. Based on that the code can better decide when vmalloc and ioremap
 * mapping changes need to be synchronized to other page-tables in the system.
 */
#define     __PGTBL_PGD_MODIFIED    0
#define     __PGTBL_P4D_MODIFIED    1
#define     __PGTBL_PUD_MODIFIED    2
#define     __PGTBL_PMD_MODIFIED    3
#define     __PGTBL_PTE_MODIFIED    4

#define     PGTBL_PGD_MODIFIED  BIT(__PGTBL_PGD_MODIFIED)
#define     PGTBL_P4D_MODIFIED  BIT(__PGTBL_P4D_MODIFIED)
#define     PGTBL_PUD_MODIFIED  BIT(__PGTBL_PUD_MODIFIED)
#define     PGTBL_PMD_MODIFIED  BIT(__PGTBL_PMD_MODIFIED)
#define     PGTBL_PTE_MODIFIED  BIT(__PGTBL_PTE_MODIFIED)

/* Page-Table Modification Mask */
typedef unsigned int pgtbl_mod_mask;

/*
 * When walking page tables, we usually want to skip any p?d_none entries;
 * and any p?d_bad entries - reporting the error before resetting to none.
 * Do the tests inline, but report and clear the bad entry in mm/memory.c.
 */
void pgd_clear_bad(pgd_t *);

void p4d_clear_bad(p4d_t *);

void pud_clear_bad(pud_t *);

void pmd_clear_bad(pmd_t *);

static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
    if (pgd_none(*pgd))
        return 1;
    if (unlikely(pgd_bad(*pgd))) {
        pgd_clear_bad(pgd);
        return 1;
    }
    return 0;
}

static inline int p4d_none_or_clear_bad(p4d_t *p4d)
{
    if (p4d_none(*p4d))
        return 1;
    if (unlikely(p4d_bad(*p4d))) {
        p4d_clear_bad(p4d);
        return 1;
    }
    return 0;
}

static inline int pud_none_or_clear_bad(pud_t *pud)
{
    if (pud_none(*pud))
        return 1;
    if (unlikely(pud_bad(*pud))) {
        pud_clear_bad(pud);
        return 1;
    }
    return 0;
}

static inline int pmd_none_or_clear_bad(pmd_t *pmd)
{
    if (pmd_none(*pmd))
        return 1;
    if (unlikely(pmd_bad(*pmd))) {
        pmd_clear_bad(pmd);
        return 1;
    }
    return 0;
}

#ifndef pte_offset_kernel
static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
    return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}
#define pte_offset_kernel pte_offset_kernel
#endif

/* Find an entry in the second-level page table.. */
#ifndef pmd_offset
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
    return pud_pgtable(*pud) + pmd_index(address);
}
#define pmd_offset pmd_offset
#endif

#ifndef pud_offset
static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
{
    return p4d_pgtable(*p4d) + pud_index(address);
}
#define pud_offset pud_offset
#endif

/*
 * No-op macros that just return the current protection value. Defined here
 * because these macros can be used even if CONFIG_MMU is not defined.
 */

#ifndef pgprot_nx
#define pgprot_nx(prot) (prot)
#endif

static inline int p4d_set_huge(p4d_t *p4d, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int pud_set_huge(pud_t *pud, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int pmd_set_huge(pmd_t *pmd, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int p4d_clear_huge(p4d_t *p4d)
{
    return 0;
}
static inline int pud_clear_huge(pud_t *pud)
{
    return 0;
}
static inline int pmd_clear_huge(pmd_t *pmd)
{
    return 0;
}
static inline int p4d_free_pud_page(p4d_t *p4d, unsigned long addr)
{
    return 0;
}
static inline int pud_free_pmd_page(pud_t *pud, unsigned long addr)
{
    return 0;
}
static inline int pmd_free_pte_page(pmd_t *pmd, unsigned long addr)
{
    return 0;
}

/*
 * On some architectures hardware does not set page access bit when accessing
 * memory page, it is responsibility of software setting this bit. It brings
 * out extra page fault penalty to track page access bit. For optimization page
 * access bit can be set during all page fault flow on these arches.
 * To be differentiate with macro pte_mkyoung, this macro is used on platforms
 * where software maintains page access bit.
 */
#ifndef pte_sw_mkyoung
static inline pte_t pte_sw_mkyoung(pte_t pte)
{
    return pte;
}
#define pte_sw_mkyoung  pte_sw_mkyoung
#endif

static inline int pmd_trans_huge(pmd_t pmd)
{
    return 0;
}
#ifndef pmd_write
static inline int pmd_write(pmd_t pmd)
{
    BUG();
    return 0;
}
#endif /* pmd_write */

/*
 * Technically a PTE can be PROTNONE even when not doing NUMA balancing but
 * the only case the kernel cares is for NUMA balancing and is only ever set
 * when the VMA is accessible. For PROT_NONE VMAs, the PTEs are not marked
 * _PAGE_PROTNONE so by default, implement the helper as "always no". It
 * is the responsibility of the caller to distinguish between PROT_NONE
 * protections and NUMA hinting fault protections.
 */
static inline int pte_protnone(pte_t pte)
{
    return 0;
}

static inline int pmd_protnone(pmd_t pmd)
{
    return 0;
}

static inline int is_zero_pfn(unsigned long pfn)
{
    extern unsigned long zero_pfn;
    return pfn == zero_pfn;
}

static inline unsigned long my_zero_pfn(unsigned long addr)
{
    extern unsigned long zero_pfn;
    return zero_pfn;
}

#ifndef pgprot_noncached
#define pgprot_noncached(prot)  (prot)
#endif

#ifndef pgprot_writecombine
#define pgprot_writecombine pgprot_noncached
#endif

#ifndef pgprot_writethrough
#define pgprot_writethrough pgprot_noncached
#endif

#ifndef pgprot_device
#define pgprot_device pgprot_noncached
#endif

#ifndef pgprot_modify
#define pgprot_modify pgprot_modify
static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
{
    if (pgprot_val(oldprot) == pgprot_val(pgprot_noncached(oldprot)))
        newprot = pgprot_noncached(newprot);
    if (pgprot_val(oldprot) == pgprot_val(pgprot_writecombine(oldprot)))
        newprot = pgprot_writecombine(newprot);
    if (pgprot_val(oldprot) == pgprot_val(pgprot_device(oldprot)))
        newprot = pgprot_device(newprot);
    return newprot;
}
#endif

static inline int pmd_devmap(pmd_t pmd)
{
    return 0;
}
static inline int pud_devmap(pud_t pud)
{
    return 0;
}
static inline int pgd_devmap(pgd_t pgd)
{
    return 0;
}

/*
 * This is a noop if Transparent Hugepage Support is not built into
 * the kernel. Otherwise it is equivalent to
 * pmd_none_or_trans_huge_or_clear_bad(), and shall only be called in
 * places that already verified the pmd is not none and they want to
 * walk ptes while holding the mmap sem in read mode (write mode don't
 * need this). If THP is not enabled, the pmd can't go away under the
 * code even if MADV_DONTNEED runs, but if THP is enabled we need to
 * run a pmd_trans_unstable before walking the ptes after
 * split_huge_pmd returns (because it may have run when the pmd become
 * null, but then a page fault can map in a THP and not a regular page).
 */
static inline int pmd_trans_unstable(pmd_t *pmd)
{
    return 0;
}

/*
 * the ordering of these checks is important for pmds with _page_devmap set.
 * if we check pmd_trans_unstable() first we will trip the bad_pmd() check
 * inside of pmd_none_or_trans_huge_or_clear_bad(). this will end up correctly
 * returning 1 but not before it spams dmesg with the pmd_clear_bad() output.
 */
static inline int pmd_devmap_trans_unstable(pmd_t *pmd)
{
    return pmd_devmap(*pmd) || pmd_trans_unstable(pmd);
}

/*
 * If two threads concurrently fault at the same page, the thread that
 * won the race updates the PTE and its local TLB/Cache. The other thread
 * gives up, simply does nothing, and continues; on architectures where
 * software can update TLB,  local TLB can be updated here to avoid next page
 * fault. This function updates TLB only, do nothing with cache or others.
 * It is the difference with function update_mmu_cache.
 */
#ifndef __HAVE_ARCH_UPDATE_MMU_TLB
static inline void update_mmu_tlb(struct vm_area_struct *vma,
                                  unsigned long address, pte_t *ptep)
{
}
#define __HAVE_ARCH_UPDATE_MMU_TLB
#endif

#ifndef flush_tlb_fix_spurious_fault
#define flush_tlb_fix_spurious_fault(vma, address) flush_tlb_page(vma, address)
#endif

/*
 * On almost all architectures and configurations, 0 can be used as the
 * upper ceiling to free_pgtables(): on many architectures it has the same
 * effect as using TASK_SIZE.  However, there is one configuration which
 * must impose a more careful limit, to avoid freeing kernel pgtables.
 */
#ifndef USER_PGTABLES_CEILING
#define USER_PGTABLES_CEILING   0UL
#endif

/*
 * This defines the first usable user address. Platforms
 * can override its value with custom FIRST_USER_ADDRESS
 * defined in their respective <asm/pgtable.h>.
 */
#ifndef FIRST_USER_ADDRESS
#define FIRST_USER_ADDRESS  0UL
#endif

/*
 * This defines the generic helper for accessing PMD page
 * table page. Although platforms can still override this
 * via their respective <asm/pgtable.h>.
 */
#ifndef pmd_pgtable
#define pmd_pgtable(pmd) pmd_page(pmd)
#endif

#ifndef pte_accessible
# define pte_accessible(mm, pte)    ((void)(pte), 1)
#endif

#ifndef __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
int ptep_clear_flush_young(struct vm_area_struct *vma,
                           unsigned long address, pte_t *ptep);
#endif

#ifndef __HAVE_ARCH_PTEP_CLEAR_FLUSH
extern pte_t ptep_clear_flush(struct vm_area_struct *vma,
                              unsigned long address,
                              pte_t *ptep);
#endif

#ifndef __HAVE_ARCH_PTE_UNUSED
/*
 * Some architectures provide facilities to virtualization guests
 * so that they can flag allocated pages as unused. This allows the
 * host to transparently reclaim unused pages. This function returns
 * whether the pte's page is unused.
 */
static inline int pte_unused(pte_t pte)
{
    return 0;
}
#endif

#endif /* !__ASSEMBLY__ */

/*
 * p?d_leaf() - true if this entry is a final mapping to a physical address.
 * This differs from p?d_huge() by the fact that they are always available (if
 * the architecture supports large pages at the appropriate level) even
 * if CONFIG_HUGETLB_PAGE is not defined.
 * Only meaningful when called on a valid entry.
 */
#ifndef pgd_leaf
#define pgd_leaf(x) 0
#endif
#ifndef p4d_leaf
#define p4d_leaf(x) 0
#endif
#ifndef pud_leaf
#define pud_leaf(x) 0
#endif
#ifndef pmd_leaf
#define pmd_leaf(x) 0
#endif

#endif /* _LINUX_PGTABLE_H */
