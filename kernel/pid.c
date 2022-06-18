// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic pidhash and scalable, time-bounded PID allocator
 *
 * (C) 2002-2003 Nadia Yvette Chambers, IBM
 * (C) 2004 Nadia Yvette Chambers, Oracle
 * (C) 2002-2004 Ingo Molnar, Red Hat
 *
 * pid-structures are backing objects for tasks sharing a given ID to chain
 * against. There is very little to them aside from hashing them and
 * parking tasks using given ID's on a list.
 *
 * The hash is always changed with the tasklist_lock write-acquired,
 * and the hash is only accessed with the tasklist_lock at least
 * read-acquired, so there's no additional SMP locking needed here.
 *
 * We have a list of bitmap pages, which bitmaps represent the PID space.
 * Allocating and freeing PIDs is completely lockless. The worst-case
 * allocation scenario when all but one out of 1 million PIDs possible are
 * allocated already: the scanning of 32 list entries and at most PAGE_SIZE
 * bytes. The typical fastpath is a single successful setbit. Freeing is O(1).
 *
 * Pid namespaces:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/memblock.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>
//#include <linux/syscalls.h>
//#include <linux/proc_ns.h>
#include <linux/refcount.h>
//#include <linux/anon_inodes.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/idr.h>
//#include <net/sock.h>
//#include <uapi/linux/pidfd.h>

struct pid init_struct_pid = {
    .count      = REFCOUNT_INIT(1),
#if 0
    .tasks      = {
        { .first = NULL },
        { .first = NULL },
        { .first = NULL },
    },
#endif
    .level      = 0,
    .numbers    = { {
        .nr     = 0,
        .ns     = &init_pid_ns,
    }, }
};

int pid_max = PID_MAX_DEFAULT;

#define RESERVED_PIDS   300

int pid_max_min = RESERVED_PIDS + 1;
int pid_max_max = PID_MAX_LIMIT;

/*
 * PID-map pages start out as NULL, they get allocated upon
 * first use and are never deallocated. This way a low pid_max
 * value does not cause lots of bitmaps to be allocated, but
 * the scheme scales to up to 4 million PIDs, runtime.
 */
struct pid_namespace init_pid_ns = {
#if 0
    .ns.count = REFCOUNT_INIT(2),
#endif
    .idr = IDR_INIT(init_pid_ns.idr),
    .pid_allocated = PIDNS_ADDING,
    .level = 0,
    .child_reaper = &init_task,
#if 0
    .user_ns = &init_user_ns,
    .ns.inum = PROC_PID_INIT_INO,
    .ns.ops = &pidns_operations,
#endif
};
EXPORT_SYMBOL_GPL(init_pid_ns);

/*
 * Note: disable interrupts while the pidmap_lock is held as an
 * interrupt might come in and do read_lock(&tasklist_lock).
 *
 * If we don't disable interrupts there is a nasty deadlock between
 * detach_pid()->free_pid() and another cpu that does
 * spin_lock(&pidmap_lock) followed by an interrupt routine that does
 * read_lock(&tasklist_lock);
 *
 * After we clean up the tasklist_lock and know there are no
 * irq handlers that take it we can leave the interrupts enabled.
 * For now it is easier to be safe than to prove it can't happen.
 */

static __cacheline_aligned_in_smp DEFINE_SPINLOCK(pidmap_lock);

static struct pid **task_pid_ptr(struct task_struct *task, enum pid_type type)
{
    return (type == PIDTYPE_PID) ?
        &task->thread_pid :
        &task->signal->pids[type];
}

struct pid *get_task_pid(struct task_struct *task, enum pid_type type)
{
    struct pid *pid;
    rcu_read_lock();
    pid = get_pid(rcu_dereference(*task_pid_ptr(task, type)));
    rcu_read_unlock();
    return pid;
}
EXPORT_SYMBOL_GPL(get_task_pid);

struct pid_namespace *task_active_pid_ns(struct task_struct *tsk)
{
    return ns_of_pid(task_pid(tsk));
}
EXPORT_SYMBOL_GPL(task_active_pid_ns);

pid_t pid_vnr(struct pid *pid)
{
    return pid_nr_ns(pid, task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(pid_vnr);

pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
    struct upid *upid;
    pid_t nr = 0;

    if (pid && ns->level <= pid->level) {
        upid = &pid->numbers[ns->level];
        if (upid->ns == ns)
            nr = upid->nr;
    }
    return nr;
}
EXPORT_SYMBOL_GPL(pid_nr_ns);

struct pid *
alloc_pid(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size)
{
    struct pid *pid;
    enum pid_type type;
    int i, nr;
    struct pid_namespace *tmp;
    struct upid *upid;
    int retval = -ENOMEM;

    /*
     * set_tid_size contains the size of the set_tid array. Starting at
     * the most nested currently active PID namespace it tells alloc_pid()
     * which PID to set for a process in that most nested PID namespace
     * up to set_tid_size PID namespaces. It does not have to set the PID
     * for a process in all nested PID namespaces but set_tid_size must
     * never be greater than the current ns->level + 1.
     */
    if (set_tid_size > ns->level + 1)
        return ERR_PTR(-EINVAL);

    pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
    if (!pid)
        return ERR_PTR(retval);

    tmp = ns;
    pid->level = ns->level;

    for (i = ns->level; i >= 0; i--) {
        int tid = 0;

        if (set_tid_size) {
            panic("%s: set_tid_size(%ld)\n", __func__, set_tid_size);
#if 0
            tid = set_tid[ns->level - i];

            retval = -EINVAL;
            if (tid < 1 || tid >= pid_max)
                goto out_free;
            /*
             * Also fail if a PID != 1 is requested and
             * no PID 1 exists.
             */
            if (tid != 1 && !tmp->child_reaper)
                goto out_free;
            retval = -EPERM;
            if (!checkpoint_restore_ns_capable(tmp->user_ns))
                goto out_free;
            set_tid_size--;
#endif
        }

        idr_preload(GFP_KERNEL);
        spin_lock_irq(&pidmap_lock);

        if (tid) {
            nr = idr_alloc(&tmp->idr, NULL, tid, tid + 1, GFP_ATOMIC);
            /*
             * If ENOSPC is returned it means that the PID is
             * alreay in use. Return EEXIST in that case.
             */
            if (nr == -ENOSPC)
                nr = -EEXIST;
        } else {
            int pid_min = 1;
            /*
             * init really needs pid 1, but after reaching the
             * maximum wrap back to RESERVED_PIDS
             */
            if (idr_get_cursor(&tmp->idr) > RESERVED_PIDS)
                pid_min = RESERVED_PIDS;

            /*
             * Store a null pointer so find_pid_ns does not find
             * a partially initialized PID (see below).
             */
            nr = idr_alloc_cyclic(&tmp->idr, NULL,
                                  pid_min, pid_max, GFP_ATOMIC);
        }
        spin_unlock_irq(&pidmap_lock);
        idr_preload_end();

    }

    panic("%s: level(%u) END!\n", __func__, ns->level);
}

void __init pid_idr_init(void)
{
    /* Verify no one has done anything silly: */
    BUILD_BUG_ON(PID_MAX_LIMIT >= PIDNS_ADDING);

    /* bump default and minimum pid_max based on number of cpus */
    pid_max = min(pid_max_max,
                  max_t(int, pid_max,
                        PIDS_PER_CPU_DEFAULT * num_possible_cpus()));
    pid_max_min = max_t(int, pid_max_min,
                        PIDS_PER_CPU_MIN * num_possible_cpus());
    pr_info("pid_max: default: %u minimum: %u\n", pid_max, pid_max_min);

    idr_init(&init_pid_ns.idr);

    init_pid_ns.pid_cachep =
        KMEM_CACHE(pid, SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT);
}
