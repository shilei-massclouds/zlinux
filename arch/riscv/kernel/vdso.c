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
//#include <linux/time_namespace.h>

//#include <vdso/datapage.h>

extern char vdso_start[], vdso_end[];

enum vvar_pages {
    VVAR_DATA_PAGE_OFFSET,
    VVAR_TIMENS_PAGE_OFFSET,
    VVAR_NR_PAGES,
};

#define VVAR_SIZE  (VVAR_NR_PAGES << PAGE_SHIFT)

struct __vdso_info {
    const char *name;
    const char *vdso_code_start;
    const char *vdso_code_end;
    unsigned long vdso_pages;
    /* Data Mapping */
    struct vm_special_mapping *dm;
    /* Code Mapping */
    struct vm_special_mapping *cm;
};

static struct __vdso_info vdso_info __ro_after_init = {
    .name = "vdso",
    .vdso_code_start = vdso_start,
    .vdso_code_end = vdso_end,
};

static int __setup_additional_pages(struct mm_struct *mm,
                                    struct linux_binprm *bprm,
                                    int uses_interp)
{
    unsigned long vdso_base, vdso_text_len, vdso_mapping_len;
    void *ret;

    BUILD_BUG_ON(VVAR_NR_PAGES != __VVAR_PAGES);

    vdso_text_len = vdso_info.vdso_pages << PAGE_SHIFT;
    /* Be sure to map the data page */
    vdso_mapping_len = vdso_text_len + VVAR_SIZE;

    panic("%s: END!\n", __func__);
}

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
