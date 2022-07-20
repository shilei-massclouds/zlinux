/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
//#include <linux/workqueue.h>
#include <linux/rwsem.h>
//#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/uidgid.h>

struct ucounts;

enum ucount_type {
    UCOUNT_USER_NAMESPACES,
    UCOUNT_PID_NAMESPACES,
    UCOUNT_UTS_NAMESPACES,
    UCOUNT_IPC_NAMESPACES,
    UCOUNT_NET_NAMESPACES,
    UCOUNT_MNT_NAMESPACES,
    UCOUNT_CGROUP_NAMESPACES,
    UCOUNT_TIME_NAMESPACES,
    UCOUNT_INOTIFY_INSTANCES,
    UCOUNT_INOTIFY_WATCHES,
    UCOUNT_RLIMIT_NPROC,
    UCOUNT_RLIMIT_MSGQUEUE,
    UCOUNT_RLIMIT_SIGPENDING,
    UCOUNT_RLIMIT_MEMLOCK,
    UCOUNT_COUNTS,
};

#define MAX_PER_NAMESPACE_UCOUNTS UCOUNT_RLIMIT_NPROC

struct user_namespace {
#if 0
    struct uid_gid_map  uid_map;
    struct uid_gid_map  gid_map;
    struct uid_gid_map  projid_map;
#endif
    struct user_namespace   *parent;
    int         level;
    kuid_t          owner;
    kgid_t          group;
    struct ns_common    ns;
    unsigned long       flags;
    /* parent_could_setfcap: true if the creator if this ns had CAP_SETFCAP
     * in its effective capability set at the child ns creation time. */
    bool            parent_could_setfcap;

    /* List of joinable keyrings in this namespace.  Modification access of
     * these pointers is controlled by keyring_sem.  Once
     * user_keyring_register is set, it won't be changed, so it can be
     * accessed directly with READ_ONCE().
     */
    struct list_head    keyring_name_list;
    struct key      *user_keyring_register;
    struct rw_semaphore keyring_sem;

#if 0
    struct work_struct  work;
    struct ctl_table_set    set;
    struct ctl_table_header *sysctls;
#endif
    struct ucounts      *ucounts;
    long ucount_max[UCOUNT_COUNTS];
} __randomize_layout;

struct ucounts {
    struct hlist_node node;
    struct user_namespace *ns;
    kuid_t uid;
    atomic_t count;
    atomic_long_t ucount[UCOUNT_COUNTS];
};

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
    if (ns)
        refcount_inc(&ns->ns.count);
    return ns;
}

extern void __put_user_ns(struct user_namespace *ns);

static inline void put_user_ns(struct user_namespace *ns)
{
    if (ns && refcount_dec_and_test(&ns->ns.count))
        __put_user_ns(ns);
}

#endif /* _LINUX_USER_H */
