/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UTSNAME_H
#define _LINUX_UTSNAME_H

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/err.h>
#include <uapi/linux/utsname.h>

struct uts_namespace {
    struct new_utsname name;
    struct user_namespace *user_ns;
    struct ucounts *ucounts;
    struct ns_common ns;
} __randomize_layout;
extern struct uts_namespace init_uts_ns;

static inline struct new_utsname *utsname(void)
{
    return &current->nsproxy->uts_ns->name;
}

static inline struct new_utsname *init_utsname(void)
{
    return &init_uts_ns.name;
}

extern struct rw_semaphore uts_sem;

extern struct user_namespace init_user_ns;

static inline void get_uts_ns(struct uts_namespace *ns)
{
    refcount_inc(&ns->ns.count);
}

extern struct uts_namespace *
copy_utsname(unsigned long flags, struct user_namespace *user_ns,
             struct uts_namespace *old_ns);
extern void free_uts_ns(struct uts_namespace *ns);

static inline void put_uts_ns(struct uts_namespace *ns)
{
    if (refcount_dec_and_test(&ns->ns.count))
        free_uts_ns(ns);
}

void uts_ns_init(void);

#endif /* _LINUX_UTSNAME_H */
