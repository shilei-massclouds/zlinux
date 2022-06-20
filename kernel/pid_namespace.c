// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pid namespaces
 *
 * Authors:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/pid.h>
#include <linux/pid_namespace.h>
#if 0
#include <linux/user_namespace.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#endif
#include <linux/err.h>
//#include <linux/acct.h>
#include <linux/slab.h>
#if 0
#include <linux/proc_ns.h>
#include <linux/reboot.h>
#endif
#include <linux/export.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/idr.h>

void put_pid_ns(struct pid_namespace *ns)
{
    panic("%s: END!\n", __func__);
#if 0
    struct pid_namespace *parent;

    while (ns != &init_pid_ns) {
        parent = ns->parent;
        if (!refcount_dec_and_test(&ns->ns.count))
            break;
        destroy_pid_namespace(ns);
        ns = parent;
    }
#endif
}
EXPORT_SYMBOL_GPL(put_pid_ns);
