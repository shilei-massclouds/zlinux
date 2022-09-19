// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/locks.c
 *
 * We implement four types of file locks: BSD locks, posix locks, open
 * file description locks, and leases.  For details about BSD locks,
 * see the flock(2) man page; for details about the other three, see
 * fcntl(2).
 *
 *
 * Locking conflicts and dependencies:
 * If multiple threads attempt to lock the same byte (or flock the same file)
 * only one can be granted the lock, and other must wait their turn.
 * The first lock has been "applied" or "granted", the others are "waiting"
 * and are "blocked" by the "applied" lock..
 *
 * Waiting and applied locks are all kept in trees whose properties are:
 *
 *  - the root of a tree may be an applied or waiting lock.
 *  - every other node in the tree is a waiting lock that
 *    conflicts with every ancestor of that node.
 *
 * Every such tree begins life as a waiting singleton which obviously
 * satisfies the above properties.
 *
 * The only ways we modify trees preserve these properties:
 *
 *  1. We may add a new leaf node, but only after first verifying that it
 *     conflicts with all of its ancestors.
 *  2. We may remove the root of a tree, creating a new singleton
 *     tree from the root and N new trees rooted in the immediate
 *     children.
 *  3. If the root of a tree is not currently an applied lock, we may
 *     apply it (if possible).
 *  4. We may upgrade the root of the tree (either extend its range,
 *     or upgrade its entire range from read to write).
 *
 * When an applied lock is modified in a way that reduces or downgrades any
 * part of its range, we remove all its children (2 above).  This particularly
 * happens when a lock is unlocked.
 *
 * For each of those child trees we "wake up" the thread which is
 * waiting for the lock so it can continue handling as follows: if the
 * root of the tree applies, we do so (3).  If it doesn't, it must
 * conflict with some applied lock.  We remove (wake up) all of its children
 * (2), and add it is a new leaf to the tree rooted in the applied
 * lock (1).  We then repeat the process recursively with those
 * children.
 *
 */
//#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/hashtable.h>
#include <linux/percpu.h>
#include <linux/sysctl.h>

#define CREATE_TRACE_POINTS
//#include <trace/events/filelock.h>

#include <linux/uaccess.h>

/*
 * This function is called when the file is being removed
 * from the task's fd array.  POSIX locks belonging to this task
 * are deleted at this time.
 */
void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
#if 0
    int error;
    struct inode *inode = locks_inode(filp);
    struct file_lock lock;
    struct file_lock_context *ctx;

    /*
     * If there are no locks held on this file, we don't need to call
     * posix_lock_file().  Another process could be setting a lock on this
     * file at the same time, but we wouldn't remove that lock anyway.
     */
    ctx = smp_load_acquire(&inode->i_flctx);
    if (!ctx || list_empty(&ctx->flc_posix))
        return;
#endif

    pr_warn("%s: NO implementation!\n", __func__);
}
EXPORT_SYMBOL(locks_remove_posix);
