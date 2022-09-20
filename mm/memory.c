// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
//#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
//#include <linux/delayacct.h>
#include <linux/init.h>
//#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
#include <linux/string.h>
#if 0
#include <linux/debugfs.h>
#endif
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
#include <linux/numa.h>
//#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
//#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

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

static unsigned long fault_around_bytes __read_mostly =
    rounddown_pow_of_two(65536);

unsigned long highest_memmap_pfn __read_mostly;

/*
 * Parameter block passed down to zap_pte_range in exceptional cases.
 */
struct zap_details {
    struct folio *single_folio; /* Locked folio to be unmapped */
    bool even_cows;             /* Zap COWed private pages too? */
};

#if defined(SPLIT_RSS_COUNTING)
#error "NOT SPLIT_RSS_COUNTING!"
#else
#define inc_mm_counter_fast(mm, member) inc_mm_counter(mm, member)
#define dec_mm_counter_fast(mm, member) dec_mm_counter(mm, member)
#endif

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
        entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
                                      vma->vm_page_prot));
        vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
                                       vmf->address, &vmf->ptl);
        if (!pte_none(*vmf->pte)) {
            update_mmu_tlb(vma, vmf->address, vmf->pte);
            goto unlock;
        }
        ret = check_stable_address_space(vma->vm_mm);
        if (ret)
            goto unlock;
        /* Deliver the page fault to userland, check inside PT lock */
        if (userfaultfd_missing(vma)) {
            pte_unmap_unlock(vmf->pte, vmf->ptl);
            return handle_userfault(vmf, VM_UFFD_MISSING);
        }
        goto setpte;
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

    inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
    page_add_new_anon_rmap(page, vma, vmf->address, false);
    lru_cache_add_inactive_or_unevictable(page, vma);

 setpte:
    set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

    /* No need to invalidate - it was non-present before */
    update_mmu_cache(vma, vmf->address, vmf->pte);
 unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    printk("%s: FAULT_FLAG_WRITE ret(%d)\n", __func__, ret);
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
 * The mmap_lock must have been held on entry, and may have been
 * released depending on flags and vma->vm_ops->fault() return value.
 * See filemap_fault() and __lock_page_retry().
 */
static vm_fault_t __do_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    vm_fault_t ret;

    /*
     * Preallocate pte before we take page_lock because this might lead to
     * deadlocks for memcg reclaim which waits for pages under writeback:
     *              lock_page(A)
     *              SetPageWriteback(A)
     *              unlock_page(A)
     * lock_page(B)
     *              lock_page(B)
     * pte_alloc_one
     *   shrink_page_list
     *     wait_on_page_writeback(A)
     *              SetPageWriteback(B)
     *              unlock_page(B)
     *              # flush A, B to clear the writeback
     */
    if (pmd_none(*vmf->pmd) && !vmf->prealloc_pte) {
        vmf->prealloc_pte = pte_alloc_one(vma->vm_mm);
        if (!vmf->prealloc_pte)
            return VM_FAULT_OOM;
    }

    ret = vma->vm_ops->fault(vmf);
    if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY |
                        VM_FAULT_DONE_COW)))
        return ret;

    if (unlikely(PageHWPoison(vmf->page))) {
        panic("%s: PageHWPoison!\n", __func__);
    }

    if (unlikely(!(ret & VM_FAULT_LOCKED)))
        lock_page(vmf->page);
    else
        VM_BUG_ON_PAGE(!PageLocked(vmf->page), vmf->page);

    printk("%s: END!\n", __func__);
    return ret;
}

#ifndef arch_wants_old_prefaulted_pte
static inline bool arch_wants_old_prefaulted_pte(void)
{
    /*
     * Transitioning a PTE from 'old' to 'young' can be expensive on
     * some architectures, even if it's performed in hardware. By
     * default, "false" means prefaulted entries will be 'young'.
     */
    return false;
}
#endif

void do_set_pte(struct vm_fault *vmf, struct page *page, unsigned long addr)
{
    struct vm_area_struct *vma = vmf->vma;
    bool write = vmf->flags & FAULT_FLAG_WRITE;
    bool prefault = vmf->address != addr;
    pte_t entry;

    flush_icache_page(vma, page);
    entry = mk_pte(page, vma->vm_page_prot);

    if (prefault && arch_wants_old_prefaulted_pte())
        entry = pte_mkold(entry);
    else
        entry = pte_sw_mkyoung(entry);

    if (write)
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);
    /* copy-on-write page */
    if (write && !(vma->vm_flags & VM_SHARED)) {
        inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
        page_add_new_anon_rmap(page, vma, addr, false);
        lru_cache_add_inactive_or_unevictable(page, vma);
    } else {
        inc_mm_counter_fast(vma->vm_mm, mm_counter_file(page));
        page_add_file_rmap(page, vma, false);
    }
    printk("%s: addr(%lx) entry(%lx)\n", __func__, addr, entry);
    set_pte_at(vma->vm_mm, addr, vmf->pte, entry);
}

vm_fault_t do_set_pmd(struct vm_fault *vmf, struct page *page)
{
    return VM_FAULT_FALLBACK;
}

/**
 * finish_fault - finish page fault once we have prepared the page to fault
 *
 * @vmf: structure describing the fault
 *
 * This function handles all that is needed to finish a page fault once the
 * page to fault in is prepared. It handles locking of PTEs, inserts PTE for
 * given page, adds reverse page mapping, handles memcg charges and LRU
 * addition.
 *
 * The function expects the page to be locked and on success it consumes a
 * reference of a page being mapped (for the PTE which maps it).
 *
 * Return: %0 on success, %VM_FAULT_ code in case of error.
 */
vm_fault_t finish_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct page *page;
    vm_fault_t ret;

    /* Did we COW the page? */
    if ((vmf->flags & FAULT_FLAG_WRITE) && !(vma->vm_flags & VM_SHARED))
        page = vmf->cow_page;
    else
        page = vmf->page;

    /*
     * check even for read faults because we might have lost our CoWed
     * page
     */
    if (!(vma->vm_flags & VM_SHARED)) {
        ret = check_stable_address_space(vma->vm_mm);
        if (ret)
            return ret;
    }

    if (pmd_none(*vmf->pmd)) {
        if (PageTransCompound(page)) {
            ret = do_set_pmd(vmf, page);
            if (ret != VM_FAULT_FALLBACK)
                return ret;
        }

        if (vmf->prealloc_pte)
            pmd_install(vma->vm_mm, vmf->pmd, &vmf->prealloc_pte);
        else if (unlikely(pte_alloc(vma->vm_mm, vmf->pmd)))
            return VM_FAULT_OOM;
    }

    /* See comment in handle_pte_fault() */
    if (pmd_devmap_trans_unstable(vmf->pmd))
        return 0;

    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
                                   vmf->address, &vmf->ptl);
    ret = 0;
    /* Re-check under ptl */
    if (likely(pte_none(*vmf->pte)))
        do_set_pte(vmf, page, vmf->address);
    else
        ret = VM_FAULT_NOPAGE;

    update_mmu_tlb(vma, vmf->address, vmf->pte);
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return ret;
}

static vm_fault_t do_shared_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    vm_fault_t ret, tmp;

    panic("%s: END!\n", __func__);
}

static vm_fault_t do_cow_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    vm_fault_t ret;

    if (unlikely(anon_vma_prepare(vma)))
        return VM_FAULT_OOM;

    vmf->cow_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
    if (!vmf->cow_page)
        return VM_FAULT_OOM;

    ret = __do_fault(vmf);
    if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
        goto uncharge_out;
    if (ret & VM_FAULT_DONE_COW)
        return ret;

    copy_user_highpage(vmf->cow_page, vmf->page, vmf->address, vma);
    __SetPageUptodate(vmf->cow_page);

    ret |= finish_fault(vmf);
    unlock_page(vmf->page);
    put_page(vmf->page);
    if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
        goto uncharge_out;
    printk("%s: END!\n", __func__);
    return ret;
 uncharge_out:
    put_page(vmf->cow_page);
    return ret;
}

/*
 * do_fault_around() tries to map few pages around the fault address. The hope
 * is that the pages will be needed soon and this will lower the number of
 * faults to handle.
 *
 * It uses vm_ops->map_pages() to map the pages, which skips the page if it's
 * not ready to be mapped: not up-to-date, locked, etc.
 *
 * This function is called with the page table lock taken. In the split ptlock
 * case the page table lock only protects only those entries which belong to
 * the page table corresponding to the fault address.
 *
 * This function doesn't cross the VMA boundaries, in order to call map_pages()
 * only once.
 *
 * fault_around_bytes defines how many bytes we'll try to map.
 * do_fault_around() expects it to be set to a power of two less than or equal
 * to PTRS_PER_PTE.
 *
 * The virtual address of the area that we map is naturally aligned to
 * fault_around_bytes rounded down to the machine page size
 * (and therefore to page order).  This way it's easier to guarantee
 * that we don't cross page table boundaries.
 */
static vm_fault_t do_fault_around(struct vm_fault *vmf)
{
    unsigned long address = vmf->address, nr_pages, mask;
    pgoff_t start_pgoff = vmf->pgoff;
    pgoff_t end_pgoff;
    int off;

    nr_pages = READ_ONCE(fault_around_bytes) >> PAGE_SHIFT;
    mask = ~(nr_pages * PAGE_SIZE - 1) & PAGE_MASK;

    address = max(address & mask, vmf->vma->vm_start);
    off = ((vmf->address - address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
    start_pgoff -= off;

    /*
     *  end_pgoff is either the end of the page table, the end of
     *  the vma or nr_pages from start_pgoff, depending what is nearest.
     */
    end_pgoff = start_pgoff - ((address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)) +
        PTRS_PER_PTE - 1;
    end_pgoff = min3(end_pgoff, vma_pages(vmf->vma) + vmf->vma->vm_pgoff - 1,
                     start_pgoff + nr_pages - 1);

    if (pmd_none(*vmf->pmd)) {
        vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
        if (!vmf->prealloc_pte)
            return VM_FAULT_OOM;
    }

    return vmf->vma->vm_ops->map_pages(vmf, start_pgoff, end_pgoff);
}

static vm_fault_t do_read_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    vm_fault_t ret = 0;

    /*
     * Let's call ->map_pages() first and use ->fault() as fallback
     * if page by the offset is not ready to be mapped (cold cache or
     * something).
     */
    if (vma->vm_ops->map_pages && fault_around_bytes >> PAGE_SHIFT > 1) {
        ret = do_fault_around(vmf);
        if (ret)
            return ret;
    }

    ret = __do_fault(vmf);
    if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
                        VM_FAULT_RETRY)))
        return ret;

    ret |= finish_fault(vmf);
    unlock_page(vmf->page);
    if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE |
                        VM_FAULT_RETRY)))
        put_page(vmf->page);
    return ret;
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

    /*
     * The VMA was not fully populated on mmap() or missing VM_DONTEXPAND
     */
    if (!vma->vm_ops->fault) {
        panic("%s: has no fault!\n", __func__);
    } else if (!(vmf->flags & FAULT_FLAG_WRITE)) {
        ret = do_read_fault(vmf);
    } else if (!(vma->vm_flags & VM_SHARED)) {
        ret = do_cow_fault(vmf);
    } else {
        ret = do_shared_fault(vmf);
    }

    /* preallocated pagetable is unused: free it */
    if (vmf->prealloc_pte) {
        pte_free(vm_mm, vmf->prealloc_pte);
        vmf->prealloc_pte = NULL;
    }

    printk("%s: END!\n", __func__);
    return ret;
}

/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with pte unmapped and unlocked.
 *
 * We return with the mmap_lock locked or unlocked in the same cases
 * as does filemap_fault().
 */
vm_fault_t do_swap_page(struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

static vm_fault_t do_numa_page(struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

/*
 * Handle write page faults for VM_MIXEDMAP or VM_PFNMAP for a VM_SHARED
 * mapping
 */
static vm_fault_t wp_pfn_shared(struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

static inline bool cow_user_page(struct page *dst, struct page *src,
                                 struct vm_fault *vmf)
{
    bool ret;
    void *kaddr;
    void __user *uaddr;
    bool locked = false;
    struct vm_area_struct *vma = vmf->vma;
    struct mm_struct *mm = vma->vm_mm;
    unsigned long addr = vmf->address;

    if (likely(src)) {
        copy_user_highpage(dst, src, addr, vma);
        return true;
    }

    panic("%s: END!\n", __func__);
}

/*
 * Handle the case of a page which we actually need to copy to a new page.
 *
 * Called with mmap_lock locked and the old page referenced, but
 * without the ptl held.
 *
 * High level logic flow:
 *
 * - Allocate a page, copy the content of the old page to the new one.
 * - Handle book keeping and accounting - cgroups, mmu-notifiers, etc.
 * - Take the PTL. If the pte changed, bail out and release the allocated page
 * - If the pte is still the way we remember it, update the page table and all
 *   relevant references. This includes dropping the reference the page-table
 *   held to the old page, as well as updating the rmap.
 * - In any case, unlock the PTL and drop the reference we took to the old page.
 */
static vm_fault_t wp_page_copy(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct mm_struct *mm = vma->vm_mm;
    struct page *old_page = vmf->page;
    struct page *new_page = NULL;
    pte_t entry;
    int page_copied = 0;
    struct mmu_notifier_range range;

    printk("%s: 1\n", __func__);
    if (unlikely(anon_vma_prepare(vma)))
        goto oom;

    if (is_zero_pfn(pte_pfn(vmf->orig_pte))) {
        new_page = alloc_zeroed_user_highpage_movable(vma, vmf->address);
        if (!new_page)
            goto oom;
    } else {
        new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->address);
        if (!new_page)
            goto oom;

        if (!cow_user_page(new_page, old_page, vmf)) {
            /*
             * COW failed, if the fault was solved by other,
             * it's fine. If not, userspace would re-fault on
             * the same address and we will handle the fault
             * from the second attempt.
             */
            put_page(new_page);
            if (old_page)
                put_page(old_page);
            return 0;
        }
    }

    __SetPageUptodate(new_page);

    mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, mm,
                            vmf->address & PAGE_MASK,
                            (vmf->address & PAGE_MASK) + PAGE_SIZE);
    mmu_notifier_invalidate_range_start(&range);

    /*
     * Re-check the pte - we dropped the lock
     */
    vmf->pte = pte_offset_map_lock(mm, vmf->pmd, vmf->address, &vmf->ptl);
    if (likely(pte_same(*vmf->pte, vmf->orig_pte))) {
        if (old_page) {
            if (!PageAnon(old_page)) {
                dec_mm_counter_fast(mm, mm_counter_file(old_page));
                inc_mm_counter_fast(mm, MM_ANONPAGES);
            }
        } else {
            inc_mm_counter_fast(mm, MM_ANONPAGES);
        }
        flush_cache_page(vma, vmf->address, pte_pfn(vmf->orig_pte));
        entry = mk_pte(new_page, vma->vm_page_prot);
        entry = pte_sw_mkyoung(entry);
        entry = maybe_mkwrite(pte_mkdirty(entry), vma);

        /*
         * Clear the pte entry and flush it first, before updating the
         * pte with the new entry, to keep TLBs on different CPUs in
         * sync. This code used to set the new PTE then flush TLBs, but
         * that left a window where the new PTE could be loaded into
         * some TLBs while the old PTE remains in others.
         */
        ptep_clear_flush_notify(vma, vmf->address, vmf->pte);
        page_add_new_anon_rmap(new_page, vma, vmf->address, false);
        lru_cache_add_inactive_or_unevictable(new_page, vma);
        /*
         * We call the notify macro here because, when using secondary
         * mmu page tables (such as kvm shadow page tables), we want the
         * new page to be mapped directly into the secondary page table.
         */
        set_pte_at_notify(mm, vmf->address, vmf->pte, entry);
        update_mmu_cache(vma, vmf->address, vmf->pte);

        if (old_page) {
            /*
             * Only after switching the pte to the new page may
             * we remove the mapcount here. Otherwise another
             * process may come and find the rmap count decremented
             * before the pte is switched to the new page, and
             * "reuse" the old page writing into it while our pte
             * here still points into it and can be read by other
             * threads.
             *
             * The critical issue is to order this
             * page_remove_rmap with the ptp_clear_flush above.
             * Those stores are ordered by (if nothing else,)
             * the barrier present in the atomic_add_negative
             * in page_remove_rmap.
             *
             * Then the TLB flush in ptep_clear_flush ensures that
             * no process can access the old page before the
             * decremented mapcount is visible. And the old page
             * cannot be reused until after the decremented
             * mapcount is visible. So transitively, TLBs to
             * old page will be flushed before it can be reused.
             */
            page_remove_rmap(old_page, vma, false);
        }

        /* Free the old page.. */
        new_page = old_page;
        page_copied = 1;
    } else {
        update_mmu_tlb(vma, vmf->address, vmf->pte);
    }

    if (new_page)
        put_page(new_page);

    pte_unmap_unlock(vmf->pte, vmf->ptl);
    /*
     * No need to double call mmu_notifier->invalidate_range() callback as
     * the above ptep_clear_flush_notify() did already call it.
     */
    mmu_notifier_invalidate_range_only_end(&range);
    if (old_page) {
        if (page_copied)
            free_swap_cache(old_page);
        put_page(old_page);
    }
    return page_copied ? VM_FAULT_WRITE : 0;
 oom_free_new:
    put_page(new_page);
 oom:
    if (old_page)
        put_page(old_page);
    return VM_FAULT_OOM;
}

static vm_fault_t wp_page_shared(struct vm_fault *vmf)
    __releases(vmf->ptl)
{
    panic("%s: END!\n", __func__);
}

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_lock still held, but pte unmapped and unlocked.
 */
static vm_fault_t do_wp_page(struct vm_fault *vmf)
    __releases(vmf->ptl)
{
    struct vm_area_struct *vma = vmf->vma;

    vmf->page = vm_normal_page(vma, vmf->address, vmf->orig_pte);
    if (!vmf->page) {
        /*
         * VM_MIXEDMAP !pfn_valid() case, or VM_SOFTDIRTY clear on a
         * VM_PFNMAP VMA.
         *
         * We should not cow pages in a shared writeable mapping.
         * Just mark the pages writable and/or call ops->pfn_mkwrite.
         */
        if ((vma->vm_flags & (VM_WRITE|VM_SHARED)) == (VM_WRITE|VM_SHARED))
            return wp_pfn_shared(vmf);

        pte_unmap_unlock(vmf->pte, vmf->ptl);
        return wp_page_copy(vmf);
    }

    /*
     * Take out anonymous pages first, anonymous shared vmas are
     * not dirty accountable.
     */
    if (PageAnon(vmf->page)) {
        panic("%s: PageAnon!\n", __func__);
    } else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
                        (VM_WRITE|VM_SHARED))) {
        return wp_page_shared(vmf);
    }

 copy:
    /*
     * Ok, we need to copy. Oh, well..
     */
    get_page(vmf->page);

    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return wp_page_copy(vmf);
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
        /*
         * If a huge pmd materialized under us just retry later.  Use
         * pmd_trans_unstable() via pmd_devmap_trans_unstable() instead
         * of pmd_trans_huge() to ensure the pmd didn't become
         * pmd_trans_huge under us and then back to pmd_none, as a
         * result of MADV_DONTNEED running immediately after a huge pmd
         * fault in a different thread of this mm, in turn leading to a
         * misleading pmd_trans_huge() retval. All we have to ensure is
         * that it is a regular pmd that we can walk with
         * pte_offset_map() and we can do that through an atomic read
         * in C, which is what pmd_trans_unstable() provides.
         */
        if (pmd_devmap_trans_unstable(vmf->pmd))
            return 0;
        /*
         * A regular pmd is established and it can't morph into a huge
         * pmd from under us anymore at this point because we hold the
         * mmap_lock read mode and khugepaged takes it in write mode.
         * So now it's safe to run pte_offset_map().
         */
        vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
        vmf->orig_pte = *vmf->pte;

        /*
         * some architectures can have larger ptes than wordsize,
         * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and
         * CONFIG_32BIT=y, so READ_ONCE cannot guarantee atomic
         * accesses.  The code below just needs a consistent view
         * for the ifs and we later double check anyway with the
         * ptl lock held. So here a barrier will do.
         */
        barrier();
        if (pte_none(vmf->orig_pte)) {
            pte_unmap(vmf->pte);
            vmf->pte = NULL;
        }
    }

    if (!vmf->pte) {
        if (vma_is_anonymous(vmf->vma))
            return do_anonymous_page(vmf);
        else
            return do_fault(vmf);
    }

    if (!pte_present(vmf->orig_pte))
        return do_swap_page(vmf);

    if (pte_protnone(vmf->orig_pte) && vma_is_accessible(vmf->vma))
        return do_numa_page(vmf);

    vmf->ptl = pte_lockptr(vmf->vma->vm_mm, vmf->pmd);
    spin_lock(vmf->ptl);
    entry = vmf->orig_pte;
    if (unlikely(!pte_same(*vmf->pte, entry))) {
        update_mmu_tlb(vmf->vma, vmf->address, vmf->pte);
        goto unlock;
    }
    if (vmf->flags & FAULT_FLAG_WRITE) {
        if (!pte_write(entry))
            return do_wp_page(vmf);
        entry = pte_mkdirty(entry);
    }
    entry = pte_mkyoung(entry);
    if (ptep_set_access_flags(vmf->vma, vmf->address, vmf->pte, entry,
                              vmf->flags & FAULT_FLAG_WRITE)) {
        update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
    } else {
        /* Skip spurious TLB flush for retried page fault */
        if (vmf->flags & FAULT_FLAG_TRIED)
            goto unlock;
        /*
         * This is needed only for protection faults but the arch code
         * is not yet telling us if this is a protection fault or not.
         * This still avoids useless tlb flushes for .text page faults
         * with threads.
         */
        if (vmf->flags & FAULT_FLAG_WRITE)
            flush_tlb_fix_spurious_fault(vmf->vma, vmf->address);
    }
 unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return 0;
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

    printk("+++ %s: END!\n", __func__);
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

    printk("+++ %s: END!\n", __func__);
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

static inline void init_rss_vec(int *rss)
{
    memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}

static inline void add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
    int i;

    if (current->mm == mm)
        sync_mm_rss(mm);
    for (i = 0; i < NR_MM_COUNTERS; i++)
        if (rss[i])
            add_mm_counter(mm, i, rss[i]);
}

static unsigned long
zap_pte_range(struct mmu_gather *tlb,
              struct vm_area_struct *vma, pmd_t *pmd,
              unsigned long addr, unsigned long end,
              struct zap_details *details)
{
    struct mm_struct *mm = tlb->mm;
    int force_flush = 0;
    int rss[NR_MM_COUNTERS];
    spinlock_t *ptl;
    pte_t *start_pte;
    pte_t *pte;
    swp_entry_t entry;

    tlb_change_page_size(tlb, PAGE_SIZE);

 again:
    init_rss_vec(rss);
    start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    pte = start_pte;
    flush_tlb_batched_pending(mm);
    arch_enter_lazy_mmu_mode();
    do {
        pte_t ptent = *pte;
        struct page *page;

        if (pte_none(ptent))
            continue;

        if (need_resched())
            break;

        if (pte_present(ptent)) {
            panic("%s: 0!\n", __func__);
        }

        panic("%s: 1!\n", __func__);
    } while (pte++, addr += PAGE_SIZE, addr != end);

    add_mm_rss_vec(mm, rss);
    arch_leave_lazy_mmu_mode();

    /* Do the actual TLB flush before dropping ptl */
    if (force_flush)
        tlb_flush_mmu_tlbonly(tlb);
    pte_unmap_unlock(start_pte, ptl);

    /*
     * If we forced a TLB flush (either due to running out of
     * batch buffers or because we needed to flush dirty TLB
     * entries before releasing the ptl), free the batched
     * memory too. Restart if we didn't do everything.
     */
    if (force_flush) {
        force_flush = 0;
        tlb_flush_mmu(tlb);
    }

    if (addr != end) {
        cond_resched();
        goto again;
    }

    return addr;
}

static inline
unsigned long zap_pmd_range(struct mmu_gather *tlb,
                            struct vm_area_struct *vma, pud_t *pud,
                            unsigned long addr, unsigned long end,
                            struct zap_details *details)
{
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);
    do {
        next = pmd_addr_end(addr, end);

        /*
         * Here there can be other concurrent MADV_DONTNEED or
         * trans huge page faults running, and if the pmd is
         * none or trans huge it can change under us. This is
         * because MADV_DONTNEED holds the mmap_lock in read
         * mode.
         */
        if (pmd_none_or_trans_huge_or_clear_bad(pmd))
            goto next;
        next = zap_pte_range(tlb, vma, pmd, addr, next, details);
next:
        cond_resched();
    } while (pmd++, addr = next, addr != end);

    return addr;
}

static inline
unsigned long zap_pud_range(struct mmu_gather *tlb,
                            struct vm_area_struct *vma, p4d_t *p4d,
                            unsigned long addr, unsigned long end,
                            struct zap_details *details)
{
    pud_t *pud;
    unsigned long next;

    pud = pud_offset(p4d, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none_or_clear_bad(pud))
            continue;
        next = zap_pmd_range(tlb, vma, pud, addr, next, details);
 next:
        cond_resched();
    } while (pud++, addr = next, addr != end);

    return addr;
}

static inline
unsigned long zap_p4d_range(struct mmu_gather *tlb,
                            struct vm_area_struct *vma, pgd_t *pgd,
                            unsigned long addr, unsigned long end,
                            struct zap_details *details)
{
    p4d_t *p4d;
    unsigned long next;

    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);
        if (p4d_none_or_clear_bad(p4d))
            continue;
        next = zap_pud_range(tlb, vma, p4d, addr, next, details);
    } while (p4d++, addr = next, addr != end);

    return addr;
}

void unmap_page_range(struct mmu_gather *tlb,
                      struct vm_area_struct *vma,
                      unsigned long addr, unsigned long end,
                      struct zap_details *details)
{
    pgd_t *pgd;
    unsigned long next;

    BUG_ON(addr >= end);
    tlb_start_vma(tlb, vma);
    pgd = pgd_offset(vma->vm_mm, addr);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_none_or_clear_bad(pgd))
            continue;
        next = zap_p4d_range(tlb, vma, pgd, addr, next, details);
    } while (pgd++, addr = next, addr != end);
    tlb_end_vma(tlb, vma);
}

static void unmap_single_vma(struct mmu_gather *tlb,
                             struct vm_area_struct *vma,
                             unsigned long start_addr,
                             unsigned long end_addr,
                             struct zap_details *details)
{
    unsigned long start = max(vma->vm_start, start_addr);
    unsigned long end;

    if (start >= vma->vm_end)
        return;

    end = min(vma->vm_end, end_addr);
    if (end <= vma->vm_start)
        return;

    if (start != end) {
        if (unlikely(is_vm_hugetlb_page(vma))) {
#if 0
            /*
             * It is undesirable to test vma->vm_file as it
             * should be non-null for valid hugetlb area.
             * However, vm_file will be NULL in the error
             * cleanup path of mmap_region. When
             * hugetlbfs ->mmap method fails,
             * mmap_region() nullifies vma->vm_file
             * before calling this function to clean up.
             * Since no pte has actually been setup, it is
             * safe to do nothing in this case.
             */
            if (vma->vm_file) {
                i_mmap_lock_write(vma->vm_file->f_mapping);
                __unmap_hugepage_range_final(tlb, vma, start, end,
                                             NULL);
                i_mmap_unlock_write(vma->vm_file->f_mapping);
            }
#endif
            panic("%s: END!\n", __func__);
        } else
            unmap_page_range(tlb, vma, start, end, details);
    }
}

/**
 * unmap_vmas - unmap a range of memory covered by a list of vma's
 * @tlb: address of the caller's struct mmu_gather
 * @vma: the starting vma
 * @start_addr: virtual address at which to start unmapping
 * @end_addr: virtual address at which to end unmapping
 *
 * Unmap all pages in the vma list.
 *
 * Only addresses between `start' and `end' will be unmapped.
 *
 * The VMA list must be sorted in ascending virtual address order.
 *
 * unmap_vmas() assumes that the caller will flush the whole unmapped address
 * range after unmap_vmas() returns.  So the only responsibility here is to
 * ensure that any thus-far unmapped pages are flushed before unmap_vmas()
 * drops the lock and schedules.
 */
void unmap_vmas(struct mmu_gather *tlb,
                struct vm_area_struct *vma,
                unsigned long start_addr,
                unsigned long end_addr)
{
    struct mmu_notifier_range range;

    mmu_notifier_range_init(&range, MMU_NOTIFY_UNMAP, 0,
                            vma, vma->vm_mm,
                            start_addr, end_addr);
    mmu_notifier_invalidate_range_start(&range);
    for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next)
        unmap_single_vma(tlb, vma, start_addr, end_addr, NULL);
    mmu_notifier_invalidate_range_end(&range);
}

/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
               unsigned long addr)
{
    pgtable_t token = pmd_pgtable(*pmd);
    pmd_clear(pmd);
    pte_free_tlb(tlb, token, addr);
    mm_dec_nr_ptes(tlb->mm);
}

static inline void free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
                unsigned long addr, unsigned long end,
                unsigned long floor, unsigned long ceiling)
{
    pmd_t *pmd;
    unsigned long next;
    unsigned long start;

    start = addr;
    pmd = pmd_offset(pud, addr);
    do {
        next = pmd_addr_end(addr, end);
        if (pmd_none_or_clear_bad(pmd))
            continue;
        free_pte_range(tlb, pmd, addr);
    } while (pmd++, addr = next, addr != end);

    start &= PUD_MASK;
    if (start < floor)
        return;
    if (ceiling) {
        ceiling &= PUD_MASK;
        if (!ceiling)
            return;
    }
    if (end - 1 > ceiling - 1)
        return;

    pmd = pmd_offset(pud, start);
    pud_clear(pud);
    pmd_free_tlb(tlb, pmd, start);
    mm_dec_nr_pmds(tlb->mm);
}

static inline void free_pud_range(struct mmu_gather *tlb, p4d_t *p4d,
                unsigned long addr, unsigned long end,
                unsigned long floor, unsigned long ceiling)
{
    pud_t *pud;
    unsigned long next;
    unsigned long start;

    start = addr;
    pud = pud_offset(p4d, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none_or_clear_bad(pud))
            continue;
        free_pmd_range(tlb, pud, addr, next, floor, ceiling);
    } while (pud++, addr = next, addr != end);

    start &= P4D_MASK;
    if (start < floor)
        return;
    if (ceiling) {
        ceiling &= P4D_MASK;
        if (!ceiling)
            return;
    }
    if (end - 1 > ceiling - 1)
        return;

    pud = pud_offset(p4d, start);
    p4d_clear(p4d);
    pud_free_tlb(tlb, pud, start);
    mm_dec_nr_puds(tlb->mm);
}

static inline void free_p4d_range(struct mmu_gather *tlb, pgd_t *pgd,
                                  unsigned long addr, unsigned long end,
                                  unsigned long floor, unsigned long ceiling)
{
    p4d_t *p4d;
    unsigned long next;
    unsigned long start;

    start = addr;
    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);
        if (p4d_none_or_clear_bad(p4d))
            continue;
        free_pud_range(tlb, p4d, addr, next, floor, ceiling);
    } while (p4d++, addr = next, addr != end);

    start &= PGDIR_MASK;
    if (start < floor)
        return;
    if (ceiling) {
        ceiling &= PGDIR_MASK;
        if (!ceiling)
            return;
    }
    if (end - 1 > ceiling - 1)
        return;

    p4d = p4d_offset(pgd, start);
    pgd_clear(pgd);
    p4d_free_tlb(tlb, p4d, start);
}

/*
 * This function frees user-level page tables of a process.
 */
void free_pgd_range(struct mmu_gather *tlb,
                    unsigned long addr, unsigned long end,
                    unsigned long floor, unsigned long ceiling)
{
    pgd_t *pgd;
    unsigned long next;

    /*
     * The next few lines have given us lots of grief...
     *
     * Why are we testing PMD* at this top level?  Because often
     * there will be no work to do at all, and we'd prefer not to
     * go all the way down to the bottom just to discover that.
     *
     * Why all these "- 1"s?  Because 0 represents both the bottom
     * of the address space and the top of it (using -1 for the
     * top wouldn't help much: the masks would do the wrong thing).
     * The rule is that addr 0 and floor 0 refer to the bottom of
     * the address space, but end 0 and ceiling 0 refer to the top
     * Comparisons need to use "end - 1" and "ceiling - 1" (though
     * that end 0 case should be mythical).
     *
     * Wherever addr is brought up or ceiling brought down, we must
     * be careful to reject "the opposite 0" before it confuses the
     * subsequent tests.  But what about where end is brought down
     * by PMD_SIZE below? no, end can't go down to 0 there.
     *
     * Whereas we round start (addr) and ceiling down, by different
     * masks at different levels, in order to test whether a table
     * now has no other vmas using it, so can be freed, we don't
     * bother to round floor or end up - the tests don't need that.
     */
    addr &= PMD_MASK;
    if (addr < floor) {
        addr += PMD_SIZE;
        if (!addr)
            return;
    }
    if (ceiling) {
        ceiling &= PMD_MASK;
        if (!ceiling)
            return;
    }
    if (end - 1 > ceiling - 1)
        end -= PMD_SIZE;
    if (addr > end - 1)
        return;

    /*
     * We add page table cache pages with PAGE_SIZE,
     * (see pte_free_tlb()), flush the tlb if we need
     */
    tlb_change_page_size(tlb, PAGE_SIZE);
    pgd = pgd_offset(tlb->mm, addr);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_none_or_clear_bad(pgd))
            continue;
        free_p4d_range(tlb, pgd, addr, next, floor, ceiling);
    } while (pgd++, addr = next, addr != end);
}

void free_pgtables(struct mmu_gather *tlb, struct vm_area_struct *vma,
                   unsigned long floor, unsigned long ceiling)
{
    while (vma) {
        struct vm_area_struct *next = vma->vm_next;
        unsigned long addr = vma->vm_start;

        /*
         * Hide vma from rmap and truncate_pagecache before freeing
         * pgtables
         */
        unlink_anon_vmas(vma);
        unlink_file_vma(vma);

        if (is_vm_hugetlb_page(vma)) {
            hugetlb_free_pgd_range(tlb, addr, vma->vm_end,
                                   floor, next ? next->vm_start : ceiling);
        } else {
            /*
             * Optimization: gather nearby vmas into one call down
             */
            while (next && next->vm_start <= vma->vm_end + PMD_SIZE
                   && !is_vm_hugetlb_page(next)) {
                vma = next;
                next = vma->vm_next;
                unlink_anon_vmas(vma);
                unlink_file_vma(vma);
            }
            free_pgd_range(tlb, addr, vma->vm_end,
                           floor, next ? next->vm_start : ceiling);
        }
        vma = next;
    }
}
