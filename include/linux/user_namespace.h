/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#if 0
#include <linux/nsproxy.h>
#endif
#include <linux/ns_common.h>
#include <linux/sched.h>
//#include <linux/workqueue.h>
#include <linux/rwsem.h>
//#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/uidgid.h>

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
} __randomize_layout;

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
