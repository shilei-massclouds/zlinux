// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2006 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 *
 *  Jun 2006 - namespaces support
 *             OpenVZ, SWsoft Inc.
 *             Pavel Emelianov <xemul@openvz.org>
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/pid_namespace.h>
//#include <linux/mnt_namespace.h>
#include <linux/utsname.h>
#if 0
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#endif
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/cred.h>

/*
 * called from clone.  This now handles copy for nsproxy and all
 * namespaces therein.
 */
int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
    struct nsproxy *old_ns = tsk->nsproxy;
    struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
    struct nsproxy *new_ns;

    if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
                          CLONE_NEWPID | CLONE_NEWNET |
                          CLONE_NEWCGROUP | CLONE_NEWTIME)))) {
        if (likely(old_ns->time_ns_for_children == old_ns->time_ns)) {
            get_nsproxy(old_ns);
            return 0;
        }
    }

    /*
     * CLONE_NEWIPC must detach from the undolist: after switching
     * to a new ipc namespace, the semaphore arrays from the old
     * namespace are unreachable.  In clone parlance, CLONE_SYSVSEM
     * means share undolist with parent, so we must forbid using
     * it along with CLONE_NEWIPC.
     */
    if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
        (CLONE_NEWIPC | CLONE_SYSVSEM))
        return -EINVAL;

#if 0
    new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->fs);
    if (IS_ERR(new_ns))
        return  PTR_ERR(new_ns);

    timens_on_fork(new_ns, tsk);

    tsk->nsproxy = new_ns;
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

struct nsproxy init_nsproxy = {
    .count          = ATOMIC_INIT(1),
    .uts_ns         = &init_uts_ns,
#if 0
    .ipc_ns         = &init_ipc_ns,
#endif
    .mnt_ns         = NULL,
#if 0
    .net_ns         = &init_net,
    .cgroup_ns      = &init_cgroup_ns,
    .time_ns        = &init_time_ns,
    .time_ns_for_children   = &init_time_ns,
#endif
    .pid_ns_for_children    = &init_pid_ns,
};
