// SPDX-License-Identifier: GPL-2.0
#include <linux/pagewalk.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>

/*
 * We want to know the real level where a entry is located ignoring any
 * folding of levels which may be happening. For example if p4d is folded then
 * a missing entry found at level 1 (p4d) is actually at level 0 (pgd).
 */
static int real_depth(int depth)
{
    if (depth == 3 && PTRS_PER_PMD == 1)
        depth = 2;
    if (depth == 2 && PTRS_PER_PUD == 1)
        depth = 1;
    if (depth == 1 && PTRS_PER_P4D == 1)
        depth = 0;
    return depth;
}

static int walk_hugetlb_range(unsigned long addr, unsigned long end,
                              struct mm_walk *walk)
{
    panic("%s: END!\n", __func__);
}

static int walk_pte_range_inner(pte_t *pte, unsigned long addr,
                unsigned long end, struct mm_walk *walk)
{
    const struct mm_walk_ops *ops = walk->ops;
    int err = 0;

    for (;;) {
        err = ops->pte_entry(pte, addr, addr + PAGE_SIZE, walk);
        if (err)
               break;
        if (addr >= end - PAGE_SIZE)
            break;
        addr += PAGE_SIZE;
        pte++;
    }
    return err;
}

static int walk_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
                          struct mm_walk *walk)
{
    pte_t *pte;
    int err = 0;
    spinlock_t *ptl;

    if (walk->no_vma) {
        pte = pte_offset_map(pmd, addr);
        err = walk_pte_range_inner(pte, addr, end, walk);
        pte_unmap(pte);
    } else {
        pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
        err = walk_pte_range_inner(pte, addr, end, walk);
        pte_unmap_unlock(pte, ptl);
    }

    return err;
}

static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
                          struct mm_walk *walk)
{
    pmd_t *pmd;
    unsigned long next;
    const struct mm_walk_ops *ops = walk->ops;
    int err = 0;
    int depth = real_depth(3);

    pmd = pmd_offset(pud, addr);
    do {
again:
        next = pmd_addr_end(addr, end);
        if (pmd_none(*pmd) || (!walk->vma && !walk->no_vma)) {
            if (ops->pte_hole)
                err = ops->pte_hole(addr, next, depth, walk);
            if (err)
                break;
            continue;
        }

        walk->action = ACTION_SUBTREE;

        /*
         * This implies that each ->pmd_entry() handler
         * needs to know about pmd_trans_huge() pmds
         */
        if (ops->pmd_entry)
            err = ops->pmd_entry(pmd, addr, next, walk);
        if (err)
            break;

        if (walk->action == ACTION_AGAIN)
            goto again;

        /*
         * Check this here so we only break down trans_huge
         * pages when we _need_ to
         */
        if ((!walk->vma && (pmd_leaf(*pmd) || !pmd_present(*pmd))) ||
            walk->action == ACTION_CONTINUE ||
            !(ops->pte_entry))
            continue;

        if (walk->vma) {
            if (pmd_trans_unstable(pmd))
                goto again;
        }

        err = walk_pte_range(pmd, addr, next, walk);
        if (err)
            break;
    } while (pmd++, addr = next, addr != end);

    return err;
}

static int walk_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
                          struct mm_walk *walk)
{
    pud_t *pud;
    unsigned long next;
    const struct mm_walk_ops *ops = walk->ops;
    int err = 0;
    int depth = real_depth(2);

    pud = pud_offset(p4d, addr);
    do {
 again:
        next = pud_addr_end(addr, end);
        if (pud_none(*pud) || (!walk->vma && !walk->no_vma)) {
            if (ops->pte_hole)
                err = ops->pte_hole(addr, next, depth, walk);
            if (err)
                break;
            continue;
        }

        walk->action = ACTION_SUBTREE;

        if (ops->pud_entry)
            err = ops->pud_entry(pud, addr, next, walk);
        if (err)
            break;

        if (walk->action == ACTION_AGAIN)
            goto again;

        if ((!walk->vma && (pud_leaf(*pud) || !pud_present(*pud))) ||
            walk->action == ACTION_CONTINUE ||
            !(ops->pmd_entry || ops->pte_entry))
            continue;

        if (pud_none(*pud))
            goto again;

        err = walk_pmd_range(pud, addr, next, walk);
        if (err)
            break;
    } while (pud++, addr = next, addr != end);

    return err;
}

static int walk_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
                          struct mm_walk *walk)
{
    p4d_t *p4d;
    unsigned long next;
    const struct mm_walk_ops *ops = walk->ops;
    int err = 0;
    int depth = real_depth(1);

    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);
        if (p4d_none_or_clear_bad(p4d)) {
            if (ops->pte_hole)
                err = ops->pte_hole(addr, next, depth, walk);
            if (err)
                break;
            continue;
        }
        if (ops->p4d_entry) {
            err = ops->p4d_entry(p4d, addr, next, walk);
            if (err)
                break;
        }
        if (ops->pud_entry || ops->pmd_entry || ops->pte_entry)
            err = walk_pud_range(p4d, addr, next, walk);
        if (err)
            break;
    } while (p4d++, addr = next, addr != end);

    return err;
}

static int walk_pgd_range(unsigned long addr, unsigned long end,
                          struct mm_walk *walk)
{
    pgd_t *pgd;
    unsigned long next;
    const struct mm_walk_ops *ops = walk->ops;
    int err = 0;

    if (walk->pgd)
        pgd = walk->pgd + pgd_index(addr);
    else
        pgd = pgd_offset(walk->mm, addr);

    do {
        next = pgd_addr_end(addr, end);
        if (pgd_none_or_clear_bad(pgd)) {
            if (ops->pte_hole)
                err = ops->pte_hole(addr, next, 0, walk);
            if (err)
                break;
            continue;
        }
        if (ops->pgd_entry) {
            err = ops->pgd_entry(pgd, addr, next, walk);
            if (err)
                break;
        }
        if (ops->p4d_entry || ops->pud_entry || ops->pmd_entry ||
            ops->pte_entry)
            err = walk_p4d_range(pgd, addr, next, walk);
        if (err)
            break;
    } while (pgd++, addr = next, addr != end);

    return err;
}

static int __walk_page_range(unsigned long start, unsigned long end,
                             struct mm_walk *walk)
{
    int err = 0;
    struct vm_area_struct *vma = walk->vma;
    const struct mm_walk_ops *ops = walk->ops;

    if (vma && ops->pre_vma) {
        err = ops->pre_vma(start, end, walk);
        if (err)
            return err;
    }

    if (vma && is_vm_hugetlb_page(vma)) {
        if (ops->hugetlb_entry)
            err = walk_hugetlb_range(start, end, walk);
    } else
        err = walk_pgd_range(start, end, walk);

    if (vma && ops->post_vma)
        ops->post_vma(walk);

    return err;
}

/*
 * Similar to walk_page_range() but can walk any page tables even if they are
 * not backed by VMAs. Because 'unusual' entries may be walked this function
 * will also not lock the PTEs for the pte_entry() callback. This is useful for
 * walking the kernel pages tables or page tables for firmware.
 */
int walk_page_range_novma(struct mm_struct *mm, unsigned long start,
              unsigned long end, const struct mm_walk_ops *ops,
              pgd_t *pgd,
              void *private)
{
    struct mm_walk walk = {
        .ops        = ops,
        .mm     = mm,
        .pgd        = pgd,
        .private    = private,
        .no_vma     = true
    };

    if (start >= end || !walk.mm)
        return -EINVAL;

    mmap_assert_locked(walk.mm);

    return __walk_page_range(start, end, &walk);
}
