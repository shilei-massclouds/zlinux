// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/mprotect.c
 *
 *  (C) Copyright 1994 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 *
 *  Address space accounting code   <alan@lxorguk.ukuu.org.uk>
 *  (C) Copyright 2002 Red Hat Inc, All Rights Reserved
 */

#include <linux/pagewalk.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/personality.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
//#include <linux/perf_event.h>
#include <linux/pkeys.h>
#include <linux/ksm.h>
#include <linux/uaccess.h>
#include <linux/mm_inline.h>
#include <linux/pgtable.h>
#include <linux/sched/sysctl.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

#include "internal.h"

static inline unsigned long
change_pmd_range(struct vm_area_struct *vma,
                 pud_t *pud, unsigned long addr, unsigned long end,
                 pgprot_t newprot, unsigned long cp_flags)
{
    panic("%s: END!\n", __func__);
}

static inline unsigned long
change_pud_range(struct vm_area_struct *vma,
                 p4d_t *p4d, unsigned long addr, unsigned long end,
                 pgprot_t newprot, unsigned long cp_flags)
{
    pud_t *pud;
    unsigned long next;
    unsigned long pages = 0;

    pud = pud_offset(p4d, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none_or_clear_bad(pud))
            continue;
        pages += change_pmd_range(vma, pud, addr, next, newprot,
                                  cp_flags);
    } while (pud++, addr = next, addr != end);

    return pages;
}

static inline unsigned long
change_p4d_range(struct vm_area_struct *vma,
                 pgd_t *pgd, unsigned long addr, unsigned long end,
                 pgprot_t newprot, unsigned long cp_flags)
{
    p4d_t *p4d;
    unsigned long next;
    unsigned long pages = 0;

    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);
        if (p4d_none_or_clear_bad(p4d))
            continue;
        pages += change_pud_range(vma, p4d, addr, next, newprot,
                                  cp_flags);
    } while (p4d++, addr = next, addr != end);

    return pages;
}

static unsigned long
change_protection_range(struct vm_area_struct *vma,
                        unsigned long addr, unsigned long end,
                        pgprot_t newprot, unsigned long cp_flags)
{
    struct mm_struct *mm = vma->vm_mm;
    pgd_t *pgd;
    unsigned long next;
    unsigned long start = addr;
    unsigned long pages = 0;

    BUG_ON(addr >= end);
    pgd = pgd_offset(mm, addr);
    flush_cache_range(vma, addr, end);
    inc_tlb_flush_pending(mm);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_none_or_clear_bad(pgd))
            continue;
        pages += change_p4d_range(vma, pgd, addr, next, newprot,
                                  cp_flags);
    } while (pgd++, addr = next, addr != end);

    panic("%s: END!\n", __func__);
}

unsigned long change_protection(struct vm_area_struct *vma,
                                unsigned long start,
                                unsigned long end,
                                pgprot_t newprot,
                                unsigned long cp_flags)
{
    unsigned long pages;

    BUG_ON((cp_flags & MM_CP_UFFD_WP_ALL) == MM_CP_UFFD_WP_ALL);

    if (is_vm_hugetlb_page(vma)) {
        //pages = hugetlb_change_protection(vma, start, end, newprot);
        panic("%s: 1!\n", __func__);
    }
    else
        pages = change_protection_range(vma, start, end, newprot,
                                        cp_flags);

    return pages;
}

int
mprotect_fixup(struct vm_area_struct *vma,
               struct vm_area_struct **pprev,
               unsigned long start, unsigned long end,
               unsigned long newflags)
{
    struct mm_struct *mm = vma->vm_mm;
    unsigned long oldflags = vma->vm_flags;
    long nrpages = (end - start) >> PAGE_SHIFT;
    unsigned long charged = 0;
    pgoff_t pgoff;
    int error;
    int dirty_accountable = 0;

    if (newflags == oldflags) {
        *pprev = vma;
        return 0;
    }

    /*
     * Do PROT_NONE PFN permission checks here when we can still
     * bail out without undoing a lot of state. This is a rather
     * uncommon case, so doesn't need to be very optimized.
     */
    if (arch_has_pfn_modify_check() &&
        (vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) &&
        (newflags & VM_ACCESS_FLAGS) == 0) {
#if 0
        pgprot_t new_pgprot = vm_get_page_prot(newflags);

        error = walk_page_range(current->mm, start, end,
                &prot_none_walk_ops, &new_pgprot);
        if (error)
            return error;
#endif
        panic("%s: 1!\n", __func__);
    }

    /*
     * If we make a private mapping writable we increase our commit;
     * but (without finer accounting) cannot reduce our commit if we
     * make it unwritable again. hugetlb mapping were accounted for
     * even if read-only so there is no need to account for them here
     */
    if (newflags & VM_WRITE) {
#if 0
        /* Check space limits when area turns into data. */
        if (!may_expand_vm(mm, newflags, nrpages) &&
            may_expand_vm(mm, oldflags, nrpages))
            return -ENOMEM;
        if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_HUGETLB|
                          VM_SHARED|VM_NORESERVE))) {
            charged = nrpages;
            if (security_vm_enough_memory_mm(mm, charged))
                return -ENOMEM;
            newflags |= VM_ACCOUNT;
        }
#endif
        panic("%s: 2!\n", __func__);
    }

    /*
     * First try to merge with previous and/or next vma.
     */
    pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
    *pprev = vma_merge(mm, *pprev, start, end, newflags,
                       vma->anon_vma, vma->vm_file, pgoff,
                       vma_policy(vma),
                       vma->vm_userfaultfd_ctx,
                       anon_vma_name(vma));
    if (*pprev) {
        vma = *pprev;
        VM_WARN_ON((vma->vm_flags ^ newflags) & ~VM_SOFTDIRTY);
        goto success;
    }

    *pprev = vma;

    if (start != vma->vm_start) {
        error = split_vma(mm, vma, start, 1);
        if (error)
            goto fail;
    }

    if (end != vma->vm_end) {
        error = split_vma(mm, vma, end, 0);
        if (error)
            goto fail;
    }

 success:
    /*
     * vm_flags and vm_page_prot are protected by the mmap_lock
     * held in write mode.
     */
    vma->vm_flags = newflags;
    dirty_accountable = vma_wants_writenotify(vma, vma->vm_page_prot);
    vma_set_page_prot(vma);

    change_protection(vma, start, end, vma->vm_page_prot,
                      dirty_accountable ? MM_CP_DIRTY_ACCT : 0);

    panic("%s: success!\n", __func__);
    return 0;

 fail:
    vm_unacct_memory(charged);
    return error;
}

/*
 * pkey==-1 when doing a legacy mprotect()
 */
static int do_mprotect_pkey(unsigned long start, size_t len,
                            unsigned long prot, int pkey)
{
    unsigned long nstart, end, tmp, reqprot;
    struct vm_area_struct *vma, *prev;
    int error = -EINVAL;
    const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
    const bool rier = (current->personality & READ_IMPLIES_EXEC) &&
        (prot & PROT_READ);

    start = untagged_addr(start);

    prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
    if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /* can't be both */
        return -EINVAL;

    if (start & ~PAGE_MASK)
        return -EINVAL;
    if (!len)
        return 0;
    len = PAGE_ALIGN(len);
    end = start + len;
    if (end <= start)
        return -ENOMEM;
    if (!arch_validate_prot(prot, start))
        return -EINVAL;

    reqprot = prot;

    if (mmap_write_lock_killable(current->mm))
        return -EINTR;

    /*
     * If userspace did not allocate the pkey, do not let
     * them use it here.
     */
    error = -EINVAL;
    if ((pkey != -1) && !mm_pkey_is_allocated(current->mm, pkey))
        goto out;

    vma = find_vma(current->mm, start);
    error = -ENOMEM;
    if (!vma)
        goto out;

    if (unlikely(grows & PROT_GROWSDOWN)) {
        if (vma->vm_start >= end)
            goto out;
        start = vma->vm_start;
        error = -EINVAL;
        if (!(vma->vm_flags & VM_GROWSDOWN))
            goto out;
    } else {
        if (vma->vm_start > start)
            goto out;
        if (unlikely(grows & PROT_GROWSUP)) {
            end = vma->vm_end;
            error = -EINVAL;
            if (!(vma->vm_flags & VM_GROWSUP))
                goto out;
        }
    }

    if (start > vma->vm_start)
        prev = vma;
    else
        prev = vma->vm_prev;

    for (nstart = start ; ; ) {
        unsigned long mask_off_old_flags;
        unsigned long newflags;
        int new_vma_pkey;

        /* Here we know that vma->vm_start <= nstart < vma->vm_end. */

        /* Does the application expect PROT_READ to imply PROT_EXEC */
        if (rier && (vma->vm_flags & VM_MAYEXEC))
            prot |= PROT_EXEC;

        /*
         * Each mprotect() call explicitly passes r/w/x permissions.
         * If a permission is not passed to mprotect(), it must be
         * cleared from the VMA.
         */
        mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
            VM_FLAGS_CLEAR;

        new_vma_pkey = arch_override_mprotect_pkey(vma, prot, pkey);
        newflags = calc_vm_prot_bits(prot, new_vma_pkey);
        newflags |= (vma->vm_flags & ~mask_off_old_flags);

        /* newflags >> 4 shift VM_MAY% in place of VM_% */
        if ((newflags & ~(newflags >> 4)) & VM_ACCESS_FLAGS) {
            error = -EACCES;
            goto out;
        }

        /* Allow architectures to sanity-check the new flags */
        if (!arch_validate_flags(newflags)) {
            error = -EINVAL;
            goto out;
        }

        tmp = vma->vm_end;
        if (tmp > end)
            tmp = end;

        if (vma->vm_ops && vma->vm_ops->mprotect) {
            error = vma->vm_ops->mprotect(vma, nstart, tmp, newflags);
            if (error)
                goto out;
        }

        error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
        if (error)
            goto out;

        panic("%s: 1!\n", __func__);
    }

    panic("%s: END!\n", __func__);

 out:
    mmap_write_unlock(current->mm);
    return error;
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
                unsigned long, prot)
{
    return do_mprotect_pkey(start, len, prot, -1);
}
