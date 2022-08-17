// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2004 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 */

#include <linux/export.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/sched/task.h>

static struct kmem_cache *uts_ns_cache __ro_after_init;

static inline struct uts_namespace *to_uts_ns(struct ns_common *ns)
{
    return container_of(ns, struct uts_namespace, ns);
}

static struct ns_common *utsns_get(struct task_struct *task)
{
    panic("%s: END!\n", __func__);
}

static void utsns_put(struct ns_common *ns)
{
    panic("%s: END!\n", __func__);
}

static int utsns_install(struct nsset *nsset, struct ns_common *new)
{
    panic("%s: END!\n", __func__);
}

static struct user_namespace *utsns_owner(struct ns_common *ns)
{
    return to_uts_ns(ns)->user_ns;
}

void free_uts_ns(struct uts_namespace *ns)
{
#if 0
    dec_uts_namespaces(ns->ucounts);
    put_user_ns(ns->user_ns);
    ns_free_inum(&ns->ns);
    kmem_cache_free(uts_ns_cache, ns);
#endif
    panic("%s: END!\n", __func__);
}

const struct proc_ns_operations utsns_operations = {
    .name       = "uts",
    .type       = CLONE_NEWUTS,
    .get        = utsns_get,
    .put        = utsns_put,
    .install    = utsns_install,
    .owner      = utsns_owner,
};

void __init uts_ns_init(void)
{
    uts_ns_cache = kmem_cache_create_usercopy(
            "uts_namespace", sizeof(struct uts_namespace), 0,
            SLAB_PANIC|SLAB_ACCOUNT,
            offsetof(struct uts_namespace, name),
            sizeof_field(struct uts_namespace, name),
            NULL);
}
