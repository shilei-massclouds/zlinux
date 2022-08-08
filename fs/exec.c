// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/exec.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * #!-checking implemented by tytso.
 */
/*
 * Demand-loading implemented 01.12.91 - no need to read anything but
 * the header into memory. The inode of the executable is put into
 * "current->executable", and page faults do the actual loading. Clean.
 *
 * Once more I can proudly say that linux stood up to being changed: it
 * was less than 2 hours work to get demand-loading completely implemented.
 *
 * Demand loading changed July 1993 by Eric Youngdale.   Use mmap instead,
 * current->executable is only used by the procfs.  This allows a dispatch
 * table to check for several different types  of binary formats.  We keep
 * trying until we recognize the file or we run out of supported binary
 * formats.
 */

//#include <linux/kernel_read_file.h>
#include <linux/slab.h>
#if 0
#include <linux/file.h>
#include <linux/fdtable.h>
#endif
#include <linux/mm.h>
//#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
//#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>
//#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
//#include <linux/perf_event.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#if 0
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/utsname.h>
#endif
#include <linux/binfmts.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/mount.h>
#if 0
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#endif
#include <linux/kmod.h>
#if 0
#include <linux/fsnotify.h>
#include <linux/oom.h>
#endif
#include <linux/fs_struct.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>
#if 0
#include <linux/io_uring.h>
#include <linux/syscall_user_dispatch.h>
#include <linux/coredump.h>
#endif

#include <linux/uaccess.h>
//#include <asm/mmu_context.h>
//#include <asm/tlb.h>

#include "internal.h"

static void free_bprm(struct linux_binprm *bprm)
{
    panic("%s: END!\n", __func__);
}

/*
 * Create a new mm_struct and populate it with a temporary stack
 * vm_area_struct.  We don't have enough context at this point to set the stack
 * flags, permissions, and offset, so we use temporary values.  We'll update
 * them later in setup_arg_pages().
 */
static int bprm_mm_init(struct linux_binprm *bprm)
{
    int err;
    struct mm_struct *mm = NULL;

    bprm->mm = mm = mm_alloc();
    err = -ENOMEM;
    if (!mm)
        goto err;

    panic("%s: END!\n", __func__);
    return 0;

 err:
    if (mm) {
        bprm->mm = NULL;
        mmdrop(mm);
    }

    return err;
}

static struct linux_binprm *alloc_bprm(int fd, struct filename *filename)
{
    struct linux_binprm *bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
    int retval = -ENOMEM;
    if (!bprm)
        goto out;

    if (fd == AT_FDCWD || filename->name[0] == '/') {
        bprm->filename = filename->name;
    } else {
        if (filename->name[0] == '\0')
            bprm->fdpath = kasprintf(GFP_KERNEL, "/dev/fd/%d", fd);
        else
            bprm->fdpath = kasprintf(GFP_KERNEL, "/dev/fd/%d/%s",
                                     fd, filename->name);
        if (!bprm->fdpath)
            goto out_free;

        bprm->filename = bprm->fdpath;
    }
    bprm->interp = bprm->filename;

    retval = bprm_mm_init(bprm);
    if (retval)
        goto out_free;
    return bprm;

 out_free:
    free_bprm(bprm);
 out:
    return ERR_PTR(retval);
}

int kernel_execve(const char *kernel_filename,
                  const char *const *argv, const char *const *envp)
{
    struct filename *filename;
    struct linux_binprm *bprm;
    int fd = AT_FDCWD;
    int retval;

    filename = getname_kernel(kernel_filename);
    if (IS_ERR(filename))
        return PTR_ERR(filename);

    bprm = alloc_bprm(fd, filename);
    if (IS_ERR(bprm)) {
        retval = PTR_ERR(bprm);
        goto out_ret;
    }

    panic("%s: (%s) END!\n", __func__, kernel_filename);

 out_free:
    free_bprm(bprm);
 out_ret:
    putname(filename);
    return retval;
}
