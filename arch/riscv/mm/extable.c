// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Lennox Wu <lennox.wu@sunplusct.com>
 *  Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2013 Regents of the University of California
 */

//#include <linux/bitfield.h>
//#include <linux/extable.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/asm-extable.h>
#include <asm/ptrace.h>

bool fixup_exception(struct pt_regs *regs)
{
#if 0
    const struct exception_table_entry *ex;

    ex = search_exception_tables(regs->epc);
    if (!ex)
        return false;

    switch (ex->type) {
    case EX_TYPE_FIXUP:
        return ex_handler_fixup(ex, regs);
    case EX_TYPE_BPF:
        return ex_handler_bpf(ex, regs);
    case EX_TYPE_UACCESS_ERR_ZERO:
        return ex_handler_uaccess_err_zero(ex, regs);
    }

    BUG();
#endif
    panic("%s: END!\n", __func__);
}
