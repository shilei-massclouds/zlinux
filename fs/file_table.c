// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
//#include <linux/security.h>
#include <linux/cred.h>
//#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#if 0
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#endif
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#if 0
#include <linux/task_work.h>
#include <linux/ima.h>
#endif
#include <linux/swap.h>

#include <linux/atomic.h>

#include "internal.h"

/* sysctl tunables... */
static struct files_stat_struct files_stat = {
    .max_files = NR_FILE
};

/* SLAB cache for file structures */
static struct kmem_cache *filp_cachep __read_mostly;

static struct percpu_counter nr_files __cacheline_aligned_in_smp;

void fput(struct file *file)
{
    fput_many(file, 1);
}
EXPORT_SYMBOL(fput);

void fput_many(struct file *file, unsigned int refs)
{
    if (atomic_long_sub_and_test(refs, &file->f_count)) {
#if 0
        struct task_struct *task = current;

        if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {
            init_task_work(&file->f_u.fu_rcuhead, ____fput);
            if (!task_work_add(task, &file->f_u.fu_rcuhead, TWA_RESUME))
                return;
            /*
             * After this task has run exit_task_work(),
             * task_work_add() will fail.  Fall through to delayed
             * fput to avoid leaking *file.
             */
        }

        if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
            schedule_delayed_work(&delayed_fput_work, 1);
#endif
        pr_warn("%s: no implementation!\n", __func__);
    }
}

static struct file *__alloc_file(int flags, const struct cred *cred)
{
    struct file *f;
    int error;

    f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
    if (unlikely(!f))
        return ERR_PTR(-ENOMEM);

    f->f_cred = get_cred(cred);
    atomic_long_set(&f->f_count, 1);
    rwlock_init(&f->f_owner.lock);
    spin_lock_init(&f->f_lock);
    mutex_init(&f->f_pos_lock);
    f->f_flags = flags;
    f->f_mode = OPEN_FMODE(flags);
    /* f->f_version: 0 */

    return f;
}

/*
 * Return the total number of open files in the system
 */
static long get_nr_files(void)
{
    return percpu_counter_read_positive(&nr_files);
}

/*
 * Return the maximum number of open files in the system
 */
unsigned long get_max_files(void)
{
    return files_stat.max_files;
}
EXPORT_SYMBOL_GPL(get_max_files);

/* Find an unused file structure and return a pointer to it.
 * Returns an error pointer if some error happend e.g. we over file
 * structures limit, run out of memory or operation is not permitted.
 *
 * Be very careful using this.  You are responsible for
 * getting write access to any mount that you might assign
 * to this filp, if it is opened for write.  If this is not
 * done, you will imbalance int the mount's writer count
 * and a warning at __fput() time.
 */
struct file *alloc_empty_file(int flags, const struct cred *cred)
{
    static long old_max;
    struct file *f;

    /*
     * Privileged users can go above max_files
     */
    if (get_nr_files() >= files_stat.max_files/* && !capable(CAP_SYS_ADMIN)*/) {
        /*
         * percpu_counters are inaccurate.  Do an expensive check before
         * we go and fail.
         */
        if (percpu_counter_sum_positive(&nr_files) >= files_stat.max_files)
            goto over;
    }

    f = __alloc_file(flags, cred);
    if (!IS_ERR(f))
        percpu_counter_inc(&nr_files);

    return f;

over:
    /* Ran out of filps - report that */
    if (get_nr_files() > old_max) {
        pr_info("VFS: file-max limit %lu reached\n", get_max_files());
        old_max = get_nr_files();
    }
    return ERR_PTR(-ENFILE);
}

void __init files_init(void)
{
    filp_cachep =
        kmem_cache_create("filp", sizeof(struct file), 0,
                          SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT, NULL);
    percpu_counter_init(&nr_files, 0, GFP_KERNEL);
}

/*
 * One file with associated inode and dcache is very roughly 1K. Per default
 * do not use more than 10% of our memory for files.
 */
void __init files_maxfiles_init(void)
{
    unsigned long n;
    unsigned long nr_pages = totalram_pages();
    unsigned long memreserve = (nr_pages - nr_free_pages()) * 3/2;

    memreserve = min(memreserve, nr_pages - 1);
    n = ((nr_pages - memreserve) * (PAGE_SIZE / 1024)) / 10;

    files_stat.max_files = max_t(unsigned long, n, NR_FILE);
}
