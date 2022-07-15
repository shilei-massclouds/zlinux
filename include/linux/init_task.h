/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX__INIT_TASK_H
#define _LINUX__INIT_TASK_H

#include <linux/rcupdate.h>
#include <linux/irqflags.h>
//#include <linux/utsname.h>
#include <linux/lockdep.h>
#if 0
#include <linux/ftrace.h>
#include <linux/ipc.h>
#endif
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
//#include <linux/securebits.h>
#include <linux/seqlock.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/sched/autogroup.h>
#if 0
#include <net/net_namespace.h>
#include <linux/sched/rt.h>
#include <linux/livepatch.h>
#endif
#include <linux/mm_types.h>

#include <asm/thread_info.h>

#define INIT_TASK_COMM "swapper"

extern struct nsproxy init_nsproxy;

extern struct cred init_cred;

#endif /* _LINUX__INIT_TASK_H */
