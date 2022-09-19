/* SPDX-License-Identifier: GPL-2.0 */
/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/nospec.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <linux/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG
#define NR_OPEN_MAX ~0U

struct fdtable {
    unsigned int max_fds;
    struct file __rcu **fd;      /* current fd array */
    unsigned long *close_on_exec;
    unsigned long *open_fds;
    unsigned long *full_fds_bits;
    struct rcu_head rcu;
};

/*
 * Open file table structure
 */
struct files_struct {
  /*
   * read mostly part
   */
    atomic_t count;
    bool resize_in_progress;
    wait_queue_head_t resize_wait;

    struct fdtable __rcu *fdt;
    struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
    spinlock_t file_lock ____cacheline_aligned_in_smp;
    unsigned int next_fd;
    unsigned long close_on_exec_init[1];
    unsigned long open_fds_init[1];
    unsigned long full_fds_bits_init[1];
    struct file __rcu *fd_array[NR_OPEN_DEFAULT];
};

struct files_struct *
dup_fd(struct files_struct *, unsigned, int *) __latent_entropy;

void do_close_on_exec(struct files_struct *);

extern struct kmem_cache *files_cachep;

#define rcu_dereference_check_fdtable(files, fdtfd) \
    rcu_dereference_check((fdtfd))

#define files_fdtable(files) \
    rcu_dereference_check_fdtable((files), (files)->fdt)

void put_files_struct(struct files_struct *fs);

int unshare_files(void);

/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *files_lookup_fd_raw(struct files_struct *files, unsigned int fd)
{
    struct fdtable *fdt = rcu_dereference_raw(files->fdt);

    if (fd < fdt->max_fds) {
        fd = array_index_nospec(fd, fdt->max_fds);
        return rcu_dereference_raw(fdt->fd[fd]);
    }
    return NULL;
}

#endif /* __LINUX_FDTABLE_H */
