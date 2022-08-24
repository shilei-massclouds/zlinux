/* SPDX-License-Identifier: GPL-2.0 */
/*
 * procfs namespace bits
 */
#ifndef _LINUX_PROC_NS_H
#define _LINUX_PROC_NS_H

#include <linux/ns_common.h>

struct pid_namespace;
struct nsset;
struct path;
struct task_struct;
struct inode;

struct proc_ns_operations {
    const char *name;
    const char *real_ns_name;
    int type;
    struct ns_common *(*get)(struct task_struct *task);
    void (*put)(struct ns_common *ns);
    int (*install)(struct nsset *nsset, struct ns_common *ns);
    struct user_namespace *(*owner)(struct ns_common *ns);
    struct ns_common *(*get_parent)(struct ns_common *ns);
} __randomize_layout;

extern const struct proc_ns_operations utsns_operations;

/*
 * We always define these enumerators
 */
enum {
    PROC_ROOT_INO       = 1,
    PROC_IPC_INIT_INO   = 0xEFFFFFFFU,
    PROC_UTS_INIT_INO   = 0xEFFFFFFEU,
    PROC_USER_INIT_INO  = 0xEFFFFFFDU,
    PROC_PID_INIT_INO   = 0xEFFFFFFCU,
    PROC_CGROUP_INIT_INO    = 0xEFFFFFFBU,
    PROC_TIME_INIT_INO  = 0xEFFFFFFAU,
};

extern int proc_alloc_inum(unsigned int *pino);
extern void proc_free_inum(unsigned int inum);

#endif /* _LINUX_PROC_NS_H */
