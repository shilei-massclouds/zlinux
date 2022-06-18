/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PID_NS_H
#define _LINUX_PID_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/mm.h>
//#include <linux/workqueue.h>
#include <linux/threads.h>
//#include <linux/nsproxy.h>
//#include <linux/ns_common.h>
#include <linux/idr.h>

struct fs_pin;

struct pid_namespace {
    struct idr idr;
    struct rcu_head rcu;
    unsigned int pid_allocated;
    struct task_struct *child_reaper;
    struct kmem_cache *pid_cachep;
    unsigned int level;
    struct pid_namespace *parent;
#if 0
    struct user_namespace *user_ns;
    struct ucounts *ucounts;
    int reboot; /* group exit code if this pidns was rebooted */
    struct ns_common ns;
#endif
} __randomize_layout;

extern struct pid_namespace init_pid_ns;

void pid_idr_init(void);

#define PIDNS_ADDING (1U << 31)

#endif /* _LINUX_PID_NS_H */
