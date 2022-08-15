// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Lennox Wu <lennox.wu@sunplusct.com>
 *  Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
//#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
//#include <linux/kprobes.h>
//#include <linux/kfence.h>

#include <asm/ptrace.h>
#include <asm/tlbflush.h>

#include "../kernel/head.h"

static void die_kernel_fault(const char *msg, unsigned long addr,
                             struct pt_regs *regs)
{
#if 0
    bust_spinlocks(1);

    pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n", msg,
        addr);

    bust_spinlocks(0);
    die(regs, "Oops");
    make_task_dead(SIGKILL);
#endif
    panic("%s: END!\n", __func__);
}

static inline void vmalloc_fault(struct pt_regs *regs, int code, unsigned long addr)
{
    pgd_t *pgd, *pgd_k;
    pud_t *pud, *pud_k;
    p4d_t *p4d, *p4d_k;
    pmd_t *pmd, *pmd_k;
    pte_t *pte_k;
    int index;
    unsigned long pfn;

    panic("%s: END!\n", __func__);
}

static inline void no_context(struct pt_regs *regs, unsigned long addr)
{
    panic("%s: END!\n", __func__);
}

static inline void bad_area(struct pt_regs *regs, struct mm_struct *mm,
                            int code, unsigned long addr)
{
    /*
     * Something tried to access memory that isn't in our memory map.
     * Fix it, but check if it's kernel or user first.
     */
    mmap_read_unlock(mm);
    /* User mode accesses just cause a SIGSEGV */
    if (user_mode(regs)) {
        do_trap(regs, SIGSEGV, code, addr);
        return;
    }

    no_context(regs, addr);
}

static inline bool access_error(unsigned long cause, struct vm_area_struct *vma)
{
    switch (cause) {
    case EXC_INST_PAGE_FAULT:
        if (!(vma->vm_flags & VM_EXEC)) {
            return true;
        }
        break;
    case EXC_LOAD_PAGE_FAULT:
        if (!(vma->vm_flags & VM_READ)) {
            return true;
        }
        break;
    case EXC_STORE_PAGE_FAULT:
        if (!(vma->vm_flags & VM_WRITE)) {
            return true;
        }
        break;
    default:
        panic("%s: unhandled cause %lu", __func__, cause);
    }
    return false;
}

/*
 * This routine handles page faults.  It determines the address and the
 * problem, and then passes it off to one of the appropriate routines.
 */
asmlinkage void do_page_fault(struct pt_regs *regs)
{
    struct task_struct *tsk;
    struct vm_area_struct *vma;
    struct mm_struct *mm;
    unsigned long addr, cause;
    unsigned int flags = FAULT_FLAG_DEFAULT;
    int code = SEGV_MAPERR;
    vm_fault_t fault;

    cause = regs->cause;
    addr = regs->badaddr;

    tsk = current;
    mm = tsk->mm;

    /*
     * Fault-in kernel-space virtual memory on-demand.
     * The 'reference' page table is init_mm.pgd.
     *
     * NOTE! We MUST NOT take any locks for this case. We may
     * be in an interrupt or a critical region, and should
     * only copy the information from the master page table,
     * nothing more.
     */
    if (unlikely((addr >= VMALLOC_START) && (addr < VMALLOC_END))) {
        vmalloc_fault(regs, code, addr);
        return;
    }

    /*
     * Modules in 64bit kernels lie in their own virtual region which is not
     * in the vmalloc region, but dealing with page faults in this region
     * or the vmalloc region amounts to doing the same thing: checking that
     * the mapping exists in init_mm.pgd and updating user page table, so
     * just use vmalloc_fault.
     */
    if (unlikely(addr >= MODULES_VADDR && addr < MODULES_END)) {
        vmalloc_fault(regs, code, addr);
        return;
    }

    /* Enable interrupts if they were enabled in the parent context. */
    if (likely(regs->status & SR_PIE))
        local_irq_enable();

    /*
     * If we're in an interrupt, have no user context, or are running
     * in an atomic region, then we must not take the fault.
     */
    if (unlikely(faulthandler_disabled() || !mm)) {
        tsk->thread.bad_cause = cause;
        no_context(regs, addr);
        return;
    }

    if (user_mode(regs))
        flags |= FAULT_FLAG_USER;

    if (!user_mode(regs) && addr < TASK_SIZE &&
        unlikely(!(regs->status & SR_SUM)))
        die_kernel_fault("access to user memory without uaccess routines",
                         addr, regs);

    //perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);

    if (cause == EXC_STORE_PAGE_FAULT)
        flags |= FAULT_FLAG_WRITE;
    else if (cause == EXC_INST_PAGE_FAULT)
        flags |= FAULT_FLAG_INSTRUCTION;

 retry:
    mmap_read_lock(mm);
    vma = find_vma(mm, addr);
    printk("%s: step1\n", __func__);
    if (unlikely(!vma)) {
        tsk->thread.bad_cause = cause;
        bad_area(regs, mm, code, addr);
        return;
    }
    if (likely(vma->vm_start <= addr))
        goto good_area;
    if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
        tsk->thread.bad_cause = cause;
        bad_area(regs, mm, code, addr);
        return;
    }
    if (unlikely(expand_stack(vma, addr))) {
        tsk->thread.bad_cause = cause;
        bad_area(regs, mm, code, addr);
        return;
    }

    /*
     * Ok, we have a good vm_area for this memory access, so
     * we can handle it.
     */

 good_area:
    code = SEGV_ACCERR;

    if (unlikely(access_error(cause, vma))) {
        tsk->thread.bad_cause = cause;
        bad_area(regs, mm, code, addr);
        return;
    }

    /*
     * If for any reason at all we could not handle the fault,
     * make sure we exit gracefully rather than endlessly redo
     * the fault.
     */
    fault = handle_mm_fault(vma, addr, flags, regs);

    panic("%s: END!\n", __func__);
}
