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

    vdso_base = get_unmapped_area(NULL, 0, vdso_mapping_len, 0, 0);
    if (IS_ERR_VALUE(vdso_base)) {
        ret = ERR_PTR(vdso_base);
        goto up_fail;
    }

    ret = _install_special_mapping(mm, vdso_base, VVAR_SIZE,
                                   (VM_READ | VM_MAYREAD | VM_PFNMAP),
                                   vdso_info.dm);
    if (IS_ERR(ret))
        goto up_fail;

    vdso_base += VVAR_SIZE;
    mm->context.vdso = (void *)vdso_base;
    ret = _install_special_mapping(mm, vdso_base, vdso_text_len,
                                   (VM_READ | VM_EXEC | VM_MAYREAD |
                                    VM_MAYWRITE | VM_MAYEXEC),
                                   vdso_info.cm);

    if (IS_ERR(ret))
        goto up_fail;

    return 0;

 up_fail:
    mm->context.vdso = NULL;
    return PTR_ERR(ret);
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

static int __init __vdso_init(void)
{
    unsigned int i;
    struct page **vdso_pagelist;
    unsigned long pfn;

    if (memcmp(vdso_info.vdso_code_start, "\177ELF", 4)) {
        pr_err("vDSO is not a valid ELF object!\n");
        return -EINVAL;
    }

    vdso_info.vdso_pages =
        (vdso_info.vdso_code_end -
         vdso_info.vdso_code_start) >> PAGE_SHIFT;

    vdso_pagelist = kcalloc(vdso_info.vdso_pages,
                            sizeof(struct page *),
                            GFP_KERNEL);
    if (vdso_pagelist == NULL)
        return -ENOMEM;

    /* Grab the vDSO code pages. */
    pfn = sym_to_pfn(vdso_info.vdso_code_start);

    for (i = 0; i < vdso_info.vdso_pages; i++)
        vdso_pagelist[i] = pfn_to_page(pfn + i);

    vdso_info.cm->pages = vdso_pagelist;

    return 0;
}

static vm_fault_t
vvar_fault(const struct vm_special_mapping *sm,
           struct vm_area_struct *vma, struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

static int vdso_mremap(const struct vm_special_mapping *sm,
                       struct vm_area_struct *new_vma)
{
    current->mm->context.vdso = (void *)new_vma->vm_start;

    return 0;
}

enum rv_vdso_map {
    RV_VDSO_MAP_VVAR,
    RV_VDSO_MAP_VDSO,
};

static struct vm_special_mapping rv_vdso_maps[] __ro_after_init = {
    [RV_VDSO_MAP_VVAR] = {
        .name   = "[vvar]",
        .fault = vvar_fault,
    },
    [RV_VDSO_MAP_VDSO] = {
        .name   = "[vdso]",
        .mremap = vdso_mremap,
    },
};

static int __init vdso_init(void)
{
    vdso_info.dm = &rv_vdso_maps[RV_VDSO_MAP_VVAR];
    vdso_info.cm = &rv_vdso_maps[RV_VDSO_MAP_VDSO];

    return __vdso_init();
}
arch_initcall(vdso_init);
