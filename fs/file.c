// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 */

//#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
//#include <linux/close_range.h>
//#include <net/sock.h>

#include "internal.h"

struct files_struct init_files = {
    .count  = ATOMIC_INIT(1),
    .fdt    = &init_files.fdtab,
    .fdtab  = {
        .max_fds        = NR_OPEN_DEFAULT,
        .fd             = &init_files.fd_array[0],
        .close_on_exec  = init_files.close_on_exec_init,
        .open_fds       = init_files.open_fds_init,
        .full_fds_bits  = init_files.full_fds_bits_init,
    },
    .file_lock      = __SPIN_LOCK_UNLOCKED(init_files.file_lock),
    .resize_wait    =
        __WAIT_QUEUE_HEAD_INITIALIZER(init_files.resize_wait),
};

bool get_close_on_exec(unsigned int fd)
{
#if 0
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    bool res;
    rcu_read_lock();
    fdt = files_fdtable(files);
    res = close_on_exec(fd, fdt);
    rcu_read_unlock();
    return res;
#endif
    panic("%s: END!\n", __func__);
}

static unsigned int count_open_files(struct fdtable *fdt)
{
    unsigned int size = fdt->max_fds;
    unsigned int i;

    /* Find the last open fd */
    for (i = size / BITS_PER_LONG; i > 0; ) {
        if (fdt->open_fds[--i])
            break;
    }
    i = (i + 1) * BITS_PER_LONG;
    return i;
}

/*
 * Note that a sane fdtable size always has to be a multiple of
 * BITS_PER_LONG, since we have bitmaps that are sized by this.
 *
 * 'max_fds' will normally already be properly aligned, but it
 * turns out that in the close_range() -> __close_range() ->
 * unshare_fd() -> dup_fd() -> sane_fdtable_size() we can end
 * up having a 'max_fds' value that isn't already aligned.
 *
 * Rather than make close_range() have to worry about this,
 * just make that BITS_PER_LONG alignment be part of a sane
 * fdtable size. Becuase that's really what it is.
 */
static unsigned int sane_fdtable_size(struct fdtable *fdt,
                                      unsigned int max_fds)
{
    unsigned int count;

    count = count_open_files(fdt);
    if (max_fds < NR_OPEN_DEFAULT)
        max_fds = NR_OPEN_DEFAULT;
    return ALIGN(min(count, max_fds), BITS_PER_LONG);
}

static void __free_fdtable(struct fdtable *fdt)
{
    kvfree(fdt->fd);
    kvfree(fdt->open_fds);
    kfree(fdt);
}

/*
 * Note how the fdtable bitmap allocations very much have to be a multiple of
 * BITS_PER_LONG. This is not only because we walk those things in chunks of
 * 'unsigned long' in some places, but simply because that is how the Linux
 * kernel bitmaps are defined to work: they are not "bits in an array of bytes",
 * they are very much "bits in an array of unsigned long".
 *
 * The ALIGN(nr, BITS_PER_LONG) here is for clarity: since we just multiplied
 * by that "1024/sizeof(ptr)" before, we already know there are sufficient
 * clear low bits. Clang seems to realize that, gcc ends up being confused.
 *
 * On a 128-bit machine, the ALIGN() would actually matter. In the meantime,
 * let's consider it documentation (and maybe a test-case for gcc to improve
 * its code generation ;)
 */
static struct fdtable *alloc_fdtable(unsigned int nr)
{
    panic("%s: END!\n", __func__);
}

#define BITBIT_NR(nr)   BITS_TO_LONGS(BITS_TO_LONGS(nr))
#define BITBIT_SIZE(nr) (BITBIT_NR(nr) * sizeof(long))

/*
 * Copy 'count' fd bits from the old table to the new table and clear the extra
 * space if any.  This does not copy the file pointers.  Called with the files
 * spinlock held for write.
 */
static void copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
                            unsigned int count)
{
    unsigned int cpy, set;

    cpy = count / BITS_PER_BYTE;
    set = (nfdt->max_fds - count) / BITS_PER_BYTE;
    memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
    memset((char *)nfdt->open_fds + cpy, 0, set);
    memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
    memset((char *)nfdt->close_on_exec + cpy, 0, set);

    cpy = BITBIT_SIZE(count);
    set = BITBIT_SIZE(nfdt->max_fds) - cpy;
    memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
    memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
    __clear_bit(fd, fdt->open_fds);
    __clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

/*
 * Allocate a new files structure and copy contents from the
 * passed in files structure.
 * errorp will be valid only when the returned files_struct is NULL.
 */
struct files_struct *dup_fd(struct files_struct *oldf,
                            unsigned int max_fds, int *errorp)
{
    struct files_struct *newf;
    struct file **old_fds, **new_fds;
    unsigned int open_files, i;
    struct fdtable *old_fdt, *new_fdt;

    *errorp = -ENOMEM;
    newf = kmem_cache_alloc(files_cachep, GFP_KERNEL);
    if (!newf)
        goto out;

    atomic_set(&newf->count, 1);

    spin_lock_init(&newf->file_lock);
    newf->resize_in_progress = false;
    init_waitqueue_head(&newf->resize_wait);
    newf->next_fd = 0;
    new_fdt = &newf->fdtab;
    new_fdt->max_fds = NR_OPEN_DEFAULT;
    new_fdt->close_on_exec = newf->close_on_exec_init;
    new_fdt->open_fds = newf->open_fds_init;
    new_fdt->full_fds_bits = newf->full_fds_bits_init;
    new_fdt->fd = &newf->fd_array[0];

    spin_lock(&oldf->file_lock);
    old_fdt = files_fdtable(oldf);
    open_files = sane_fdtable_size(old_fdt, max_fds);

    /*
     * Check whether we need to allocate a larger fd array and fd set.
     */
    while (unlikely(open_files > new_fdt->max_fds)) {
        spin_unlock(&oldf->file_lock);

        if (new_fdt != &newf->fdtab)
            __free_fdtable(new_fdt);

        new_fdt = alloc_fdtable(open_files - 1);
        if (!new_fdt) {
            *errorp = -ENOMEM;
            goto out_release;
        }

        /* beyond sysctl_nr_open; nothing to do */
        if (unlikely(new_fdt->max_fds < open_files)) {
            __free_fdtable(new_fdt);
            *errorp = -EMFILE;
            goto out_release;
        }

        /*
         * Reacquire the oldf lock and a pointer to its fd table
         * who knows it may have a new bigger fd table. We need
         * the latest pointer.
         */
        spin_lock(&oldf->file_lock);
        old_fdt = files_fdtable(oldf);
        open_files = sane_fdtable_size(old_fdt, max_fds);
    }

    copy_fd_bitmaps(new_fdt, old_fdt, open_files);

    old_fds = old_fdt->fd;
    new_fds = new_fdt->fd;

    for (i = open_files; i != 0; i--) {
        struct file *f = *old_fds++;
        if (f) {
            get_file(f);
        } else {
            /*
             * The fd may be claimed in the fd bitmap but not yet
             * instantiated in the files array if a sibling thread
             * is partway through open().  So make sure that this
             * fd is available to the new process.
             */
            __clear_open_fd(open_files - i, new_fdt);
        }
        rcu_assign_pointer(*new_fds++, f);
    }
    spin_unlock(&oldf->file_lock);

    /* clear the remainder */
    memset(new_fds, 0,
           (new_fdt->max_fds - open_files) * sizeof(struct file *));

    rcu_assign_pointer(newf->fdt, new_fdt);

    return newf;

 out_release:
    kmem_cache_free(files_cachep, newf);
 out:
    return NULL;
}

static struct fdtable *close_files(struct files_struct * files)
{
    /*
     * It is safe to dereference the fd table without RCU or
     * ->file_lock because this is the last reference to the
     * files structure.
     */
    struct fdtable *fdt = rcu_dereference_raw(files->fdt);
    unsigned int i, j = 0;

    for (;;) {
        unsigned long set;
        i = j * BITS_PER_LONG;
        if (i >= fdt->max_fds)
            break;
        set = fdt->open_fds[j++];
        while (set) {
            if (set & 1) {
                struct file * file = xchg(&fdt->fd[i], NULL);
                if (file) {
                    filp_close(file, files);
                    cond_resched();
                }
            }
            i++;
            set >>= 1;
        }
    }

    return fdt;
}

void put_files_struct(struct files_struct *files)
{
    if (atomic_dec_and_test(&files->count)) {
        struct fdtable *fdt = close_files(files);

        /* free the arrays if they are not embedded */
        if (fdt != &files->fdtab)
            __free_fdtable(fdt);
        kmem_cache_free(files_cachep, files);
    }
}

static inline
void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->close_on_exec);
}

static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->open_fds);
    fd /= BITS_PER_LONG;
    if (!~fdt->open_fds[fd])
        __set_bit(fd, fdt->full_fds_bits);
}

static inline
void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    if (test_bit(fd, fdt->close_on_exec))
        __clear_bit(fd, fdt->close_on_exec);
}

void do_close_on_exec(struct files_struct *files)
{
    unsigned i;
    struct fdtable *fdt;

    /* exec unshares first */
    spin_lock(&files->file_lock);
    for (i = 0; ; i++) {
        unsigned long set;
        unsigned fd = i * BITS_PER_LONG;
        fdt = files_fdtable(files);
        if (fd >= fdt->max_fds)
            break;
        set = fdt->close_on_exec[i];
        if (!set)
            continue;

        fdt->close_on_exec[i] = 0;
#if 0
        for ( ; set ; fd++, set >>= 1) {
            struct file *file;
            if (!(set & 1))
                continue;
            file = fdt->fd[fd];
            if (!file)
                continue;
            rcu_assign_pointer(fdt->fd[fd], NULL);
            __put_unused_fd(files, fd);
            spin_unlock(&files->file_lock);
            filp_close(file, files);
            cond_resched();
            spin_lock(&files->file_lock);
        }
#endif
        panic("%s: 1!\n", __func__);
    }
    spin_unlock(&files->file_lock);
}

static unsigned int find_next_fd(struct fdtable *fdt,
                                 unsigned int start)
{
    unsigned int maxfd = fdt->max_fds;
    unsigned int maxbit = maxfd / BITS_PER_LONG;
    unsigned int bitbit = start / BITS_PER_LONG;

    bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) *
        BITS_PER_LONG;
    if (bitbit > maxfd)
        return maxfd;
    if (bitbit > start)
        start = bitbit;
    return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_files(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *fdt;
    int expanded = 0;

 repeat:
    fdt = files_fdtable(files);

    /* Do we need to expand? */
    if (nr < fdt->max_fds)
        return expanded;

    panic("%s: END!\n", __func__);
}

/*
 * allocate a file descriptor, mark it busy.
 */
static int alloc_fd(unsigned start, unsigned end, unsigned flags)
{
    struct files_struct *files = current->files;
    unsigned int fd;
    int error;
    struct fdtable *fdt;

    spin_lock(&files->file_lock);
repeat:
    fdt = files_fdtable(files);
    fd = start;
    if (fd < files->next_fd)
        fd = files->next_fd;

    if (fd < fdt->max_fds)
        fd = find_next_fd(fdt, fd);

    /*
     * N.B. For clone tasks sharing a files structure, this test
     * will limit the total number of files that can be opened.
     */
    error = -EMFILE;
    if (fd >= end)
        goto out;

    error = expand_files(files, fd);
    if (error < 0)
        goto out;

    /*
     * If we needed to expand the fs array we
     * might have blocked - try again.
     */
    if (error)
        goto repeat;

    if (start <= files->next_fd)
        files->next_fd = fd + 1;

    __set_open_fd(fd, fdt);
    if (flags & O_CLOEXEC)
        __set_close_on_exec(fd, fdt);
    else
        __clear_close_on_exec(fd, fdt);
    error = fd;

    /* Sanity check */
    if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
        printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
        rcu_assign_pointer(fdt->fd[fd], NULL);
    }

 out:
    spin_unlock(&files->file_lock);
    return error;
}

int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
    return alloc_fd(0, nofile, flags);
}

int get_unused_fd_flags(unsigned flags)
{
    return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}
EXPORT_SYMBOL(get_unused_fd_flags);

/*
 * Install a file pointer in the fd array.
 *
 * The VFS is full of places where we drop the files lock between
 * setting the open_fds bitmap and installing the file in the file
 * array.  At any such point, we are vulnerable to a dup2() race
 * installing a file in the array before us.  We need to detect this and
 * fput() the struct file we are about to overwrite in this case.
 *
 * It should never happen - if we allow dup2() do it, _really_ bad things
 * will follow.
 *
 * This consumes the "file" refcount, so callers should treat it
 * as if they had called fput(file).
 */
void fd_install(unsigned int fd, struct file *file)
{
    struct files_struct *files = current->files;
    struct fdtable *fdt;

    rcu_read_lock_sched();

    panic("%s: END!\n", __func__);
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
    struct fdtable *fdt = files_fdtable(files);
    __clear_open_fd(fd, fdt);
    if (fd < files->next_fd)
        files->next_fd = fd;
}

void put_unused_fd(unsigned int fd)
{
    struct files_struct *files = current->files;
    spin_lock(&files->file_lock);
    __put_unused_fd(files, fd);
    spin_unlock(&files->file_lock);
}

EXPORT_SYMBOL(put_unused_fd);
