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

static int __bprm_mm_init(struct linux_binprm *bprm)
{
    int err;
    struct vm_area_struct *vma = NULL;
    struct mm_struct *mm = bprm->mm;

    bprm->vma = vma = vm_area_alloc(mm);
    if (!vma)
        return -ENOMEM;
    vma_set_anonymous(vma);

    if (mmap_write_lock_killable(mm)) {
        err = -EINTR;
        goto err_free;
    }

    /*
     * Place the stack at the largest stack address the architecture
     * supports. Later, we'll move this to an appropriate place. We don't
     * use STACK_TOP because that can depend on attributes which aren't
     * configured yet.
     */
    BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
    vma->vm_end = STACK_TOP_MAX;
    vma->vm_start = vma->vm_end - PAGE_SIZE;
    vma->vm_flags = VM_SOFTDIRTY | VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

    err = insert_vm_struct(mm, vma);
    if (err)
        goto err;

    mm->stack_vm = mm->total_vm = 1;
    mmap_write_unlock(mm);
    bprm->p = vma->vm_end - sizeof(void *);
    return 0;
 err:
    mmap_write_unlock(mm);
 err_free:
    bprm->vma = NULL;
    vm_area_free(vma);
    return err;
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

    /* Save current stack limit for all calculations made during exec. */
    task_lock(current->group_leader);
    bprm->rlim_stack = current->signal->rlim[RLIMIT_STACK];
    task_unlock(current->group_leader);

    err = __bprm_mm_init(bprm);
    if (err)
        goto err;

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

static int count_strings_kernel(const char *const *argv)
{
    int i;

    if (!argv)
        return 0;

    for (i = 0; argv[i]; ++i) {
        if (i >= MAX_ARG_STRINGS)
            return -E2BIG;
#if 0
        if (fatal_signal_pending(current))
            return -ERESTARTNOHAND;
#endif
        cond_resched();
    }
    return i;
}

static int bprm_stack_limits(struct linux_binprm *bprm)
{
    unsigned long limit, ptr_size;

    /*
     * Limit to 1/4 of the max stack size or 3/4 of _STK_LIM
     * (whichever is smaller) for the argv+env strings.
     * This ensures that:
     *  - the remaining binfmt code will not run out of stack space,
     *  - the program will have a reasonable amount of stack left
     *    to work from.
     */
    limit = _STK_LIM / 4 * 3;
    limit = min(limit, bprm->rlim_stack.rlim_cur / 4);
    /*
     * We've historically supported up to 32 pages (ARG_MAX)
     * of argument strings even with small stacks
     */
    limit = max_t(unsigned long, limit, ARG_MAX);

    /*
     * We must account for the size of all the argv and envp pointers to
     * the argv and envp strings, since they will also take up space in
     * the stack. They aren't stored until much later when we can't
     * signal to the parent that the child has run out of stack space.
     * Instead, calculate it here so it's possible to fail gracefully.
     *
     * In the case of argc = 0, make sure there is space for adding a
     * empty string (which will bump argc to 1), to ensure confused
     * userspace programs don't start processing from argv[1], thinking
     * argc can never be 0, to keep them from walking envp by accident.
     * See do_execveat_common().
     */
    ptr_size = (max(bprm->argc, 1) + bprm->envc) * sizeof(void *);
    if (limit <= ptr_size)
        return -E2BIG;
    limit -= ptr_size;

    bprm->argmin = bprm->p - limit;
    return 0;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
    return len <= MAX_ARG_STRLEN;
}

/*
 * The nascent bprm->mm is not visible until exec_mmap() but it can
 * use a lot of memory, account these pages in current->mm temporary
 * for oom_badness()->get_mm_rss(). Once exec succeeds or fails, we
 * change the counter back via acct_arg_size(0).
 */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
    struct mm_struct *mm = current->mm;
    long diff = (long)(pages - bprm->vma_pages);

    if (!mm || !diff)
        return;

    bprm->vma_pages = pages;
    add_mm_counter(mm, MM_ANONPAGES, diff);
}

static struct page *
get_arg_page(struct linux_binprm *bprm, unsigned long pos, int write)
{
    struct page *page;
    int ret;
    unsigned int gup_flags = FOLL_FORCE;

    if (write)
        gup_flags |= FOLL_WRITE;

    /*
     * We are doing an exec().  'current' is the process
     * doing the exec and bprm->mm is the new process's mm.
     */
    mmap_read_lock(bprm->mm);
    ret = get_user_pages_remote(bprm->mm, pos, 1, gup_flags, &page, NULL, NULL);
    mmap_read_unlock(bprm->mm);
    if (ret <= 0)
        return NULL;

    if (write)
        acct_arg_size(bprm, vma_pages(bprm->vma));

    return page;
}

static void put_arg_page(struct page *page)
{
    put_page(page);
}

static void free_arg_pages(struct linux_binprm *bprm)
{
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
                           struct page *page)
{
    flush_cache_page(bprm->vma, pos, page_to_pfn(page));
}

/*
 * Copy and argument/environment string from the kernel to the processes stack.
 */
int copy_string_kernel(const char *arg, struct linux_binprm *bprm)
{
    int len = strnlen(arg, MAX_ARG_STRLEN) + 1 /* terminating NUL */;
    unsigned long pos = bprm->p;

    if (len == 0)
        return -EFAULT;
    if (!valid_arg_len(bprm, len))
        return -E2BIG;

    /* We're going to work our way backwards. */
    arg += len;
    bprm->p -= len;
    if (bprm->p < bprm->argmin)
        return -E2BIG;

    while (len > 0) {
        unsigned int bytes_to_copy =
            min_t(unsigned int, len, min_not_zero(offset_in_page(pos),
                                                  PAGE_SIZE));
        struct page *page;
        char *kaddr;

        pos -= bytes_to_copy;
        arg -= bytes_to_copy;
        len -= bytes_to_copy;

        page = get_arg_page(bprm, pos, 1);
        if (!page)
            return -E2BIG;
        kaddr = kmap_atomic(page);
        flush_arg_page(bprm, pos & PAGE_MASK, page);
        memcpy(kaddr + offset_in_page(pos), arg, bytes_to_copy);
        flush_dcache_page(page);
        kunmap_atomic(kaddr);
        put_arg_page(page);
    }

    panic("%s: END!\n", __func__);
    return 0;
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

    retval = count_strings_kernel(argv);
    if (WARN_ON_ONCE(retval == 0))
        retval = -EINVAL;
    if (retval < 0)
        goto out_free;
    bprm->argc = retval;

    retval = count_strings_kernel(envp);
    if (retval < 0)
        goto out_free;
    bprm->envc = retval;

    retval = bprm_stack_limits(bprm);
    if (retval < 0)
        goto out_free;

    retval = copy_string_kernel(bprm->filename, bprm);
    if (retval < 0)
        goto out_free;
    bprm->exec = bprm->p;

    panic("%s: (%s) END!\n", __func__, kernel_filename);

 out_free:
    free_bprm(bprm);
 out_ret:
    putname(filename);
    return retval;
}