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

    panic("%s: END!\n", __func__);
}
