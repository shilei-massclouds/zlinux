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
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
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
#include <asm/mmu_context.h>
//#include <asm/tlb.h>

#include "internal.h"

static LIST_HEAD(formats);
static DEFINE_RWLOCK(binfmt_lock);

static void free_arg_pages(struct linux_binprm *bprm)
{
}

static inline void put_binfmt(struct linux_binfmt * fmt)
{
    module_put(fmt->module);
}

/*
 * The nascent bprm->mm is not visible until exec_mmap() but it can
 * use a lot of memory, account these pages in current->mm temporary
 * for oom_badness()->get_mm_rss(). Once exec succeeds or fails, we
 * change the counter back via acct_arg_size(0).
 */
static void acct_arg_size(struct linux_binprm *bprm,
                          unsigned long pages)
{
    struct mm_struct *mm = current->mm;
    long diff = (long)(pages - bprm->vma_pages);

    if (!mm || !diff)
        return;

    bprm->vma_pages = pages;
    add_mm_counter(mm, MM_ANONPAGES, diff);
}

static void free_bprm(struct linux_binprm *bprm)
{
    if (bprm->mm) {
        acct_arg_size(bprm, 0);
        mmput(bprm->mm);
    }
    free_arg_pages(bprm);
#if 0
    if (bprm->cred) {
        mutex_unlock(&current->signal->cred_guard_mutex);
        abort_creds(bprm->cred);
    }
    if (bprm->file) {
        allow_write_access(bprm->file);
        fput(bprm->file);
    }
    if (bprm->executable)
        fput(bprm->executable);
    /* If a binfmt changed the interp, free it. */
    if (bprm->interp != bprm->filename)
        kfree(bprm->interp);
    kfree(bprm->fdpath);
    kfree(bprm);
#endif

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

    return 0;
}

static int copy_strings_kernel(int argc, const char *const *argv,
                               struct linux_binprm *bprm)
{
    while (argc-- > 0) {
        int ret = copy_string_kernel(argv[argc], bprm);
        if (ret < 0)
            return ret;
#if 0
        if (fatal_signal_pending(current))
            return -ERESTARTNOHAND;
#endif
        cond_resched();
    }
    return 0;
}

/*
 * Prepare credentials and lock ->cred_guard_mutex.
 * setup_new_exec() commits the new creds and drops the lock.
 * Or, if exec fails before, free_bprm() should release ->cred
 * and unlock.
 */
static int prepare_bprm_creds(struct linux_binprm *bprm)
{
    if (mutex_lock_interruptible(&current->signal->cred_guard_mutex))
        return -ERESTARTNOINTR;

    bprm->cred = prepare_exec_creds();
    if (likely(bprm->cred))
        return 0;

    mutex_unlock(&current->signal->cred_guard_mutex);
    return -ENOMEM;
}

static struct file *do_open_execat(int fd, struct filename *name, int flags)
{
    struct file *file;
    int err;
    struct open_flags open_exec_flags = {
        .open_flag = O_LARGEFILE | O_RDONLY | __FMODE_EXEC,
        .acc_mode = MAY_EXEC,
        .intent = LOOKUP_OPEN,
        .lookup_flags = LOOKUP_FOLLOW,
    };

    if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
        return ERR_PTR(-EINVAL);
    if (flags & AT_SYMLINK_NOFOLLOW)
        open_exec_flags.lookup_flags &= ~LOOKUP_FOLLOW;
    if (flags & AT_EMPTY_PATH)
        open_exec_flags.lookup_flags |= LOOKUP_EMPTY;

    file = do_filp_open(fd, name, &open_exec_flags);
    if (IS_ERR(file))
        goto out;

    /*
     * may_open() has already checked for this, so it should be
     * impossible to trip now. But we need to be extra cautious
     * and check again at the very end too.
     */
    err = -EACCES;
    if (WARN_ON_ONCE(!S_ISREG(file_inode(file)->i_mode) ||
                     path_noexec(&file->f_path)))
        goto exit;

    err = deny_write_access(file);
    if (err)
        goto exit;

#if 0
    if (name->name[0] != '\0')
        fsnotify_open(file);
#endif

 out:
    return file;

 exit:
    fput(file);
    return ERR_PTR(err);
}

/*
 * Fill the binprm structure from the inode.
 * Read the first BINPRM_BUF_SIZE bytes
 *
 * This may be called multiple times for binary chains (scripts for example).
 */
static int prepare_binprm(struct linux_binprm *bprm)
{
    loff_t pos = 0;

    memset(bprm->buf, 0, BINPRM_BUF_SIZE);
    return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}

#define printable(c) \
    (((c)=='\t') || ((c)=='\n') || (0x20<=(c) && (c)<=0x7e))

/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
static int search_binary_handler(struct linux_binprm *bprm)
{
    bool need_retry = true;
    struct linux_binfmt *fmt;
    int retval;

    retval = prepare_binprm(bprm);
    if (retval < 0)
        return retval;

    retval = -ENOENT;
 retry:
    read_lock(&binfmt_lock);
    list_for_each_entry(fmt, &formats, lh) {
        if (!try_module_get(fmt->module))
            continue;
        read_unlock(&binfmt_lock);

        retval = fmt->load_binary(bprm);

        read_lock(&binfmt_lock);
        put_binfmt(fmt);
        if (bprm->point_of_no_return || (retval != -ENOEXEC)) {
            read_unlock(&binfmt_lock);
            return retval;
        }
    }
    read_unlock(&binfmt_lock);

    if (need_retry) {
        if (printable(bprm->buf[0]) && printable(bprm->buf[1]) &&
            printable(bprm->buf[2]) && printable(bprm->buf[3]))
            return retval;
#if 0
        if (request_module("binfmt-%04x",
                           *(ushort *)(bprm->buf + 2)) < 0)
            return retval;
#endif
        need_retry = false;
        goto retry;
    }

    return retval;
}

static int exec_binprm(struct linux_binprm *bprm)
{
    pid_t old_pid, old_vpid;
    int ret, depth;

    /* Need to fetch pid before load_binary changes it */
    old_pid = current->pid;
    rcu_read_lock();
    old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
    rcu_read_unlock();

    /* This allows 4 levels of binfmt rewrites before failing hard. */
    for (depth = 0;; depth++) {
        struct file *exec;
        if (depth > 5)
            return -ELOOP;

        ret = search_binary_handler(bprm);
        if (ret < 0)
            return ret;
        if (!bprm->interpreter)
            break;

        exec = bprm->file;
        bprm->file = bprm->interpreter;
        bprm->interpreter = NULL;

        allow_write_access(exec);
        if (unlikely(bprm->have_execfd)) {
            if (bprm->executable) {
                fput(exec);
                return -ENOEXEC;
            }
            bprm->executable = exec;
        } else
            fput(exec);
    }

    panic("%s: END!\n", __func__);
}

/*
 * sys_execve() executes a new program.
 */
static int bprm_execve(struct linux_binprm *bprm,
                       int fd, struct filename *filename, int flags)
{
    struct file *file;
    int retval;

    retval = prepare_bprm_creds(bprm);
    if (retval)
        return retval;

    //check_unsafe_exec(bprm);
    current->in_execve = 1;

    file = do_open_execat(fd, filename, flags);
    retval = PTR_ERR(file);
    if (IS_ERR(file))
        goto out_unmark;

    sched_exec();

    bprm->file = file;
    /*
     * Record that a name derived from an O_CLOEXEC fd will be
     * inaccessible after exec.  This allows the code in exec to
     * choose to fail when the executable is not mmaped into the
     * interpreter and an open file descriptor is not passed to
     * the interpreter.  This makes for a better user experience
     * than having the interpreter start and then immediately fail
     * when it finds the executable is inaccessible.
     */
    if (bprm->fdpath && get_close_on_exec(fd))
        bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;

    retval = exec_binprm(bprm);
    if (retval < 0)
        goto out;

    /* execve succeeded */
    current->fs->in_exec = 0;
    current->in_execve = 0;
    rseq_execve(current);

    panic("%s: END!\n", __func__);
    return retval;

 out:
    /*
     * If past the point of no return ensure the code never
     * returns to the userspace process.  Use an existing fatal
     * signal if present otherwise terminate the process with
     * SIGSEGV.
     */
#if 0
    if (bprm->point_of_no_return && !fatal_signal_pending(current))
        force_fatal_sig(SIGSEGV);
#endif

 out_unmark:
    current->fs->in_exec = 0;
    current->in_execve = 0;

    return retval;
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

    retval = copy_strings_kernel(bprm->envc, envp, bprm);
    if (retval < 0)
        goto out_free;

    retval = copy_strings_kernel(bprm->argc, argv, bprm);
    if (retval < 0)
        goto out_free;

    retval = bprm_execve(bprm, fd, filename, 0);
 out_free:
    free_bprm(bprm);
 out_ret:
    putname(filename);
    return retval;
}

bool path_noexec(const struct path *path)
{
    return (path->mnt->mnt_flags & MNT_NOEXEC) ||
           (path->mnt->mnt_sb->s_iflags & SB_I_NOEXEC);
}

void __register_binfmt(struct linux_binfmt *fmt, int insert)
{
    write_lock(&binfmt_lock);
    insert ? list_add(&fmt->lh, &formats) :
        list_add_tail(&fmt->lh, &formats);
    write_unlock(&binfmt_lock);
}
EXPORT_SYMBOL(__register_binfmt);

void unregister_binfmt(struct linux_binfmt * fmt)
{
    write_lock(&binfmt_lock);
    list_del(&fmt->lh);
    write_unlock(&binfmt_lock);
}
EXPORT_SYMBOL(unregister_binfmt);

/*
 * Compute brpm->cred based upon the final binary.
 */
static int bprm_creds_from_file(struct linux_binprm *bprm)
{
    /* Compute creds based on which file? */
    struct file *file = bprm->execfd_creds ?
        bprm->executable : bprm->file;

#if 0
    bprm_fill_uid(bprm, file);
    return security_bprm_creds_from_file(bprm, file);
#else
    return 0;
#endif
}

static int de_thread(struct task_struct *tsk)
{
    struct signal_struct *sig = tsk->signal;
    struct sighand_struct *oldsighand = tsk->sighand;
    spinlock_t *lock = &oldsighand->siglock;

    if (thread_group_empty(tsk))
        goto no_thread_group;

    panic("%s: END!\n", __func__);

 no_thread_group:
    /* we have changed execution domain */
    tsk->exit_signal = SIGCHLD;

    BUG_ON(!thread_group_leader(tsk));
    return 0;

 killed:
    /* protects against exit_notify() and __exit_signal() */
    read_lock(&tasklist_lock);
    sig->group_exec_task = NULL;
    sig->notify_count = 0;
    read_unlock(&tasklist_lock);
    return -EAGAIN;
}

/*
 * Maps the mm_struct mm into the current task struct.
 * On success, this function returns with exec_update_lock
 * held for writing.
 */
static int exec_mmap(struct mm_struct *mm)
{
    struct task_struct *tsk;
    struct mm_struct *old_mm, *active_mm;
    int ret;

    /* Notify parent that we're no longer interested in the old VM */
    tsk = current;
    old_mm = current->mm;
    exec_mm_release(tsk, old_mm);
#if 0
    if (old_mm)
        sync_mm_rss(old_mm);
#endif

    ret = down_write_killable(&tsk->signal->exec_update_lock);
    if (ret)
        return ret;

    if (old_mm) {
#if 0
        /*
         * If there is a pending fatal signal perhaps a signal
         * whose default action is to create a coredump get
         * out and die instead of going through with the exec.
         */
        ret = mmap_read_lock_killable(old_mm);
        if (ret) {
            up_write(&tsk->signal->exec_update_lock);
            return ret;
        }
#endif
        panic("%s: old_mm!\n", __func__);
    }

    task_lock(tsk);
    //membarrier_exec_mmap(mm);

    local_irq_disable();
    active_mm = tsk->active_mm;
    tsk->active_mm = mm;
    tsk->mm = mm;
    /*
     * This prevents preemption while active_mm is being loaded and
     * it and mm are being updated, which could cause problems for
     * lazy tlb mm refcounting when these are updated by context
     * switches. Not all architectures can handle irqs off over
     * activate_mm yet.
     */
    local_irq_enable();
    activate_mm(active_mm, mm);
    tsk->mm->vmacache_seqnum = 0;
    vmacache_flush(tsk);
    task_unlock(tsk);
    if (old_mm) {
#if 0
        mmap_read_unlock(old_mm);
        BUG_ON(active_mm != old_mm);
        setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
        mm_update_next_owner(old_mm);
        mmput(old_mm);
#endif
        panic("%s: 2 old_mm!\n", __func__);
        return 0;
    }
    mmdrop(active_mm);
    return 0;
}

/*
 * Calling this is the point of no return. None of the failures will be
 * seen by userspace since either the process is already taking a fatal
 * signal (via de_thread() or coredump), or will have SEGV raised
 * (after exec_mmap()) by search_binary_handler (see below).
 */
int begin_new_exec(struct linux_binprm * bprm)
{
    struct task_struct *me = current;
    int retval;

    /* Once we are committed compute the creds */
    retval = bprm_creds_from_file(bprm);
    if (retval)
        return retval;

    /*
     * Ensure all future errors are fatal.
     */
    bprm->point_of_no_return = true;

    /*
     * Make this the only thread in the thread group.
     */
    retval = de_thread(me);
    if (retval)
        goto out;

#if 0
    /*
     * Cancel any io_uring activity across execve
     */
    io_uring_task_cancel();
#endif

    /* Ensure the files table is not shared. */
    retval = unshare_files();
    if (retval)
        goto out;

    /*
     * Must be called _before_ exec_mmap() as bprm->mm is
     * not visible until then. This also enables the update
     * to be lockless.
     */
    retval = set_mm_exe_file(bprm->mm, bprm->file);
    if (retval)
        goto out;

#if 0
    /* If the binary is not readable then enforce mm->dumpable=0 */
    would_dump(bprm, bprm->file);
    if (bprm->have_execfd)
        would_dump(bprm, bprm->executable);
#endif

    /*
     * Release all of the old mmap stuff
     */
    acct_arg_size(bprm, 0);
    retval = exec_mmap(bprm->mm);
    if (retval)
        goto out;

    panic("%s: END!\n", __func__);
    return 0;

 out_unlock:
    up_write(&me->signal->exec_update_lock);
 out:
    return retval;
}
EXPORT_SYMBOL(begin_new_exec);
