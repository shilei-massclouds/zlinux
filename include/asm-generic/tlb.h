/* SPDX-License-Identifier: GPL-2.0-or-later */
/* include/asm-generic/tlb.h
 *
 *  Generic TLB shootdown code
 *
 * Copyright 2001 Red Hat, Inc.
 * Based on code from mm/memory.c Copyright Linus Torvalds and others.
 *
 * Copyright 2011 Red Hat, Inc., Peter Zijlstra
 */
#ifndef _ASM_GENERIC__TLB_H
#define _ASM_GENERIC__TLB_H

#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/hugetlb_inline.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

/*
 * struct mmu_gather is an opaque type used by the mm code for passing around
 * any data needed by arch specific code for tlb_remove_page.
 */
struct mmu_gather {
    struct mm_struct    *mm;

    unsigned long       start;
    unsigned long       end;
    /*
     * we are in the middle of an operation to clear
     * a full mm and can make some optimizations
     */
    unsigned int        fullmm : 1;

    /*
     * we have performed an operation which
     * requires a complete flush of the tlb
     */
    unsigned int        need_flush_all : 1;

    /*
     * we have removed page directories
     */
    unsigned int        freed_tables : 1;

    /*
     * at which levels have we cleared entries?
     */
    unsigned int        cleared_ptes : 1;
    unsigned int        cleared_pmds : 1;
    unsigned int        cleared_puds : 1;
    unsigned int        cleared_p4ds : 1;

    /*
     * tracks VM_EXEC | VM_HUGETLB in tlb_start_vma
     */
    unsigned int        vma_exec : 1;
    unsigned int        vma_huge : 1;

    unsigned int        batch_count;
};

#endif /* _ASM_GENERIC__TLB_H */
