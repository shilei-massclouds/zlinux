// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

//#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#if 0
#include <linux/sched/numa_balancing.h>
#include <linux/mman.h>
#endif
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#if 0
#include <linux/ksm.h>
#endif
#include <linux/rmap.h>
#include <linux/export.h>
//#include <linux/delayacct.h>
#include <linux/init.h>
/*
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
*/
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
/*
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
*/
#include <linux/oom.h>
#include <linux/numa.h>
/*
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>

#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
*/
#include <asm/pgalloc.h>

#include "pgalloc-track.h"
#include "internal.h"

/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
EXPORT_SYMBOL(max_mapnr);

struct page *mem_map;
EXPORT_SYMBOL(mem_map);

unsigned long zero_pfn __read_mostly;
EXPORT_SYMBOL(zero_pfn);

/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void *high_memory;
EXPORT_SYMBOL(high_memory);

unsigned long highest_memmap_pfn __read_mostly;

/*
 * Parameter block passed down to zap_pte_range in exceptional cases.
 */
struct zap_details {
    struct folio *single_folio; /* Locked folio to be unmapped */
    bool even_cows;             /* Zap COWed private pages too? */
};

/*
 * Allocate p4d page table.
 * We've already handled the fast-path in-line.
 */
int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
    p4d_t *new = p4d_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    spin_lock(&mm->page_table_lock);
    if (pgd_present(*pgd)) {    /* Another has populated it */
        p4d_free(mm, new);
    } else {
        smp_wmb(); /* See comment in pmd_install() */
        pgd_populate(mm, pgd, new);
    }
    spin_unlock(&mm->page_table_lock);
    return 0;
}

/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
    pud_t *new = pud_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    spin_lock(&mm->page_table_lock);
    if (!p4d_present(*p4d)) {
        mm_inc_nr_puds(mm);
        smp_wmb(); /* See comment in pmd_install() */
        p4d_populate(mm, p4d, new);
    } else  /* Another has populated it */
        pud_free(mm, new);
    spin_unlock(&mm->page_table_lock);
    return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
    spinlock_t *ptl;
    pmd_t *new = pmd_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    ptl = pud_lock(mm, pud);
    if (!pud_present(*pud)) {
        mm_inc_nr_pmds(mm);
        smp_wmb(); /* See comment in pmd_install() */
        pud_populate(mm, pud, new);
    } else {    /* Another has populated it */
        pmd_free(mm, new);
    }
    spin_unlock(ptl);
    return 0;
}

void pmd_install(struct mm_struct *mm, pmd_t *pmd, pgtable_t *pte)
{
    spinlock_t *ptl = pmd_lock(mm, pmd);

    if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
        mm_inc_nr_ptes(mm);
        /*
         * Ensure all pte setup (eg. pte page lock and page clearing) are
         * visible before the pte is made visible to other CPUs by being
         * put into page tables.
         *
         * The other side of the story is the pointer chasing in the page
         * table walking code (when walking the page table without locking;
         * ie. most of the time). Fortunately, these data accesses consist
         * of a chain of data-dependent loads, meaning most CPUs (alpha
         * being the notable exception) will already guarantee loads are
         * seen in-order. See the alpha page table accessors for the
         * smp_rmb() barriers in page table walking code.
         */
        smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
        pmd_populate(mm, pmd, *pte);
        *pte = NULL;
    }
    spin_unlock(ptl);
}

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
{
    pgtable_t new = pte_alloc_one(mm);
    if (!new)
        return -ENOMEM;

    pmd_install(mm, pmd, &new);
    if (new)
        pte_free(mm, new);
    return 0;
}

int __pte_alloc_kernel(pmd_t *pmd)
{
    pte_t *new = pte_alloc_one_kernel(&init_mm);
    if (!new)
        return -ENOMEM;

    spin_lock(&init_mm.page_table_lock);
    if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
        smp_wmb(); /* See comment in pmd_install() */
        pmd_populate_kernel(&init_mm, pmd, new);
        new = NULL;
    }
    spin_unlock(&init_mm.page_table_lock);
    if (new)
        pte_free_kernel(&init_mm, new);
    return 0;
}

void unmap_mapping_folio(struct folio *folio)
{
    struct address_space *mapping = folio->mapping;
    struct zap_details details = { };
    pgoff_t first_index;
    pgoff_t last_index;

    VM_BUG_ON(!folio_test_locked(folio));

    panic("%s: END!\n", __func__);
}

void mm_trace_rss_stat(struct mm_struct *mm, int member, long count)
{
    //trace_rss_stat(mm, member, count);
}

static gfp_t __get_fault_gfp_mask(struct vm_area_struct *vma)
{
    struct file *vm_file = vma->vm_file;

    if (vm_file)
        return mapping_gfp_mask(vm_file->f_mapping) |
            __GFP_FS | __GFP_IO;

    /*
     * Special mappings (e.g. VDSO) do not have any file so fake
     * a default GFP_KERNEL for them.
     */
    return GFP_KERNEL;
}

/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_lock still held, but pte unmapped and unlocked.
 */
static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct page *page;
    vm_fault_t ret = 0;
    pte_t entry;

    /* File mapping without ->vm_ops ? */
    if (vma->vm_flags & VM_SHARED)
        return VM_FAULT_SIGBUS;

    /*
     * Use pte_alloc() instead of pte_alloc_map().  We can't run
     * pte_offset_map() on pmds where a huge pmd might be created
     * from a different thread.
     *
     * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
     * parallel threads are excluded by other means.
     *
     * Here we only have mmap_read_lock(mm).
     */
    if (pte_alloc(vma->vm_mm, vmf->pmd))
        return VM_FAULT_OOM;

    /* Use the zero-page for reads */
    if (!(vmf->flags & FAULT_FLAG_WRITE)) {
        panic("%s: mm_forbids_zeropage!\n", __func__);
    }

    /* Allocate our own private page. */
    if (unlikely(anon_vma_prepare(vma)))
        goto oom;
    page = alloc_zeroed_user_highpage_movable(vma, vmf->address);
    if (!page)
        goto oom;

    /*
     * The memory barrier inside __SetPageUptodate makes sure that
     * preceding stores to the page contents become visible before
     * the set_pte_at() write.
     */
    __SetPageUptodate(page);

    entry = mk_pte(page, vma->vm_page_prot);
    entry = pte_sw_mkyoung(entry);
    if (vma->vm_flags & VM_WRITE)
        entry = pte_mkwrite(pte_mkdirty(entry));

    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
                                   &vmf->ptl);
    if (!pte_none(*vmf->pte)) {
        update_mmu_cache(vma, vmf->address, vmf->pte);
        goto release;
    }

    ret = check_stable_address_space(vma->vm_mm);
    if (ret)
        goto release;

    //inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
    page_add_new_anon_rmap(page, vma, vmf->address, false);
    lru_cache_add_inactive_or_unevictable(page, vma);

 setpte:
    set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

    /* No need to invalidate - it was non-present before */
    update_mmu_cache(vma, vmf->address, vmf->pte);
 unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return ret;
 release:
    put_page(page);
    goto unlock;
 oom_free_page:
    put_page(page);
 oom:
    return VM_FAULT_OOM;
}

/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults).
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 * If mmap_lock is released, vma may become invalid (for example
 * by other thread calling munmap()).
 */
static vm_fault_t do_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct mm_struct *vm_mm = vma->vm_mm;
    vm_fault_t ret;

    panic("%s: END!\n", __func__);
}

/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_lock (to exclude vma changes, but allow
 * concurrent faults).
 *
 * The mmap_lock may have been released depending on flags and our return value.
 * See filemap_fault() and __folio_lock_or_retry().
 */
static vm_fault_t handle_pte_fault(struct vm_fault *vmf)
{
    pte_t entry;

    if (unlikely(pmd_none(*vmf->pmd))) {
        /*
         * Leave __pte_alloc() until later: because vm_ops->fault may
         * want to allocate huge page, and if we expose page table
         * for an instant, it will be difficult to retract from
         * concurrent faults and from rmap lookups.
         */
        vmf->pte = NULL;
    } else {
        panic("%s: 1!\n", __func__);
    }

    if (!vmf->pte) {
        if (vma_is_anonymous(vmf->vma))
            return do_anonymous_page(vmf);
        else
            return do_fault(vmf);
    }

    panic("%s: END!\n", __func__);
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 */
static vm_fault_t
__handle_mm_fault(struct vm_area_struct *vma,
                  unsigned long address, unsigned int flags)
{
    struct vm_fault vmf = {
        .vma = vma,
        .address = address & PAGE_MASK,
        .real_address = address,
        .flags = flags,
        .pgoff = linear_page_index(vma, address),
        .gfp_mask = __get_fault_gfp_mask(vma),
    };
    unsigned int dirty = flags & FAULT_FLAG_WRITE;
    struct mm_struct *mm = vma->vm_mm;
    pgd_t *pgd;
    p4d_t *p4d;
    vm_fault_t ret;

    pgd = pgd_offset(mm, address);
    p4d = p4d_alloc(mm, pgd, address);
    if (!p4d)
        return VM_FAULT_OOM;

    vmf.pud = pud_alloc(mm, p4d, address);
    if (!vmf.pud)
        return VM_FAULT_OOM;
 retry_pud:
    barrier();

    vmf.pmd = pmd_alloc(mm, vmf.pud, address);
    if (!vmf.pmd)
        return VM_FAULT_OOM;

    vmf.orig_pmd = *vmf.pmd;

    barrier();

    return handle_pte_fault(&vmf);
}

/**
 * mm_account_fault - Do page fault accounting
 *
 * @regs: the pt_regs struct pointer.  When set to NULL, will skip accounting
 *        of perf event counters, but we'll still do the per-task accounting to
 *        the task who triggered this page fault.
 * @address: the faulted address.
 * @flags: the fault flags.
 * @ret: the fault retcode.
 *
 * This will take care of most of the page fault accounting.  Meanwhile, it
 * will also include the PERF_COUNT_SW_PAGE_FAULTS_[MAJ|MIN] perf counter
 * updates.  However, note that the handling of PERF_COUNT_SW_PAGE_FAULTS should
 * still be in per-arch page fault handlers at the entry of page fault.
 */
static inline void mm_account_fault(struct pt_regs *regs,
                    unsigned long address, unsigned int flags,
                    vm_fault_t ret)
{
    bool major;

    /*
     * We don't do accounting for some specific faults:
     *
     * - Unsuccessful faults (e.g. when the address wasn't valid).  That
     *   includes arch_vma_access_permitted() failing before reaching here.
     *   So this is not a "this many hardware page faults" counter.  We
     *   should use the hw profiling for that.
     *
     * - Incomplete faults (VM_FAULT_RETRY).  They will only be counted
     *   once they're completed.
     */
    if (ret & (VM_FAULT_ERROR | VM_FAULT_RETRY))
        return;

    /*
     * We define the fault as a major fault when the final successful fault
     * is VM_FAULT_MAJOR, or if it retried (which implies that we couldn't
     * handle it immediately previously).
     */
    major = (ret & VM_FAULT_MAJOR) || (flags & FAULT_FLAG_TRIED);

    if (major)
        current->maj_flt++;
    else
        current->min_flt++;

    /*
     * If the fault is done for GUP, regs will be NULL.  We only do the
     * accounting for the per thread fault counters who triggered the
     * fault, and we skip the perf event updates.
     */
    if (!regs)
        return;

#if 0
    if (major)
        perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
    else
        perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
#endif
}

/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __folio_lock_or_retry().
 */
vm_fault_t
handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
                unsigned int flags, struct pt_regs *regs)
{
    vm_fault_t ret;

    __set_current_state(TASK_RUNNING);

#if 0
    count_vm_event(PGFAULT);
    count_memcg_event_mm(vma->vm_mm, PGFAULT);

    /* do counter updates before entering really critical section. */
    check_sync_rss_stat(current);
#endif

    if (unlikely(is_vm_hugetlb_page(vma)))
        ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
    else
        ret = __handle_mm_fault(vma, address, flags);

    mm_account_fault(regs, address, flags, ret);

    return ret;
}

/*
 * vm_normal_page -- This function gets the "struct page" associated with a pte.
 *
 * "Special" mappings do not wish to be associated with a "struct page" (either
 * it doesn't exist, or it exists but they don't want to touch it). In this
 * case, NULL is returned here. "Normal" mappings do have a struct page.
 *
 * There are 2 broad cases. Firstly, an architecture may define a pte_special()
 * pte bit, in which case this function is trivial. Secondly, an architecture
 * may not have a spare pte bit, which requires a more complicated scheme,
 * described below.
 *
 * A raw VM_PFNMAP mapping (ie. one that is not COWed) is always considered a
 * special mapping (even if there are underlying and valid "struct pages").
 * COWed pages of a VM_PFNMAP are always normal.
 *
 * The way we recognize COWed pages within VM_PFNMAP mappings is through the
 * rules set up by "remap_pfn_range()": the vma will have the VM_PFNMAP bit
 * set, and the vm_pgoff will point to the first PFN mapped: thus every special
 * mapping will always honor the rule
 *
 *  pfn_of_page == vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT)
 *
 * And for normal mappings this is false.
 *
 * This restricts such mappings to be a linear translation from virtual address
 * to pfn. To get around this restriction, we allow arbitrary mappings so long
 * as the vma is not a COW mapping; in that case, we know that all ptes are
 * special (because none can have been COWed).
 *
 *
 * In order to support COW of arbitrary special mappings, we have VM_MIXEDMAP.
 *
 * VM_MIXEDMAP mappings can likewise contain memory with or without "struct
 * page" backing, however the difference is that _all_ pages with a struct
 * page (that is, those where pfn_valid is true) are refcounted and considered
 * normal pages by the VM. The disadvantage is that pages are refcounted
 * (which can be slower and simply not an option for some PFNMAP users). The
 * advantage is that we don't have to follow the strict linearity rule of
 * PFNMAP mappings in order to support COWable mappings.
 *
 */
struct page *
vm_normal_page(struct vm_area_struct *vma, unsigned long addr, pte_t pte)
{
    unsigned long pfn = pte_pfn(pte);

    if (likely(!pte_special(pte)))
        goto check_pfn;
    if (vma->vm_ops && vma->vm_ops->find_special_page)
        return vma->vm_ops->find_special_page(vma, addr);
    if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP))
        return NULL;
    if (is_zero_pfn(pfn))
        return NULL;

    //print_bad_pte(vma, addr, pte, NULL);
    panic("%s: END!\n", __func__);
    return NULL;

check_pfn:
    if (unlikely(pfn > highest_memmap_pfn)) {
        //print_bad_pte(vma, addr, pte, NULL);
        return NULL;
    }

    /*
     * NOTE! We still have PageReserved() pages in the page tables.
     * eg. VDSO mappings can cause them to exist.
     */
    return pfn_to_page(pfn);
}
