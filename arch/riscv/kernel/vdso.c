// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 Benjamin Herrenschmidt, IBM Corp.
 *                    <benh@kernel.crashing.org>
 * Copyright (C) 2012 ARM Limited
 * Copyright (C) 2015 Regents of the University of California
 */

#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/err.h>
#include <asm/page.h>
#include <asm/vdso.h>
#include <linux/time_namespace.h>

//#include <vdso/datapage.h>

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
    struct mm_struct *mm = current->mm;
    int ret;

    if (mmap_write_lock_killable(mm))
        return -EINTR;

    ret = __setup_additional_pages(mm, bprm, uses_interp);
    mmap_write_unlock(mm);

    return ret;
}
