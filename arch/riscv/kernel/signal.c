// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Chen Liqin <liqin.chen@sunplusct.com>
 *  Lennox Wu <lennox.wu@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/signal.h>
#include <linux/uaccess.h>
#if 0
#include <linux/syscalls.h>
#include <linux/resume_user_mode.h>
#endif
#include <linux/linkage.h>

#if 0
#include <asm/ucontext.h>
#include <asm/vdso.h>
#include <asm/switch_to.h>
#endif
#include <asm/csr.h>

/*
 * notification of userspace execution resumption
 * - triggered by the _TIF_WORK_MASK flags
 */
asmlinkage __visible void do_notify_resume(struct pt_regs *regs,
                                           unsigned long thread_info_flags)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    if (thread_info_flags & _TIF_UPROBE)
        uprobe_notify_resume(regs);

    /* Handle pending signal delivery */
    if (thread_info_flags & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
        do_signal(regs);

    if (thread_info_flags & _TIF_NOTIFY_RESUME)
        resume_user_mode_work(regs);
#endif
}
