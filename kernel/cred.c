// SPDX-License-Identifier: GPL-2.0-or-later
/* Task credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#include <linux/export.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/user.h>
#if 0
#include <linux/key.h>
#include <linux/keyctl.h>
#endif
#include <linux/init_task.h>
#if 0
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/cn_proc.h>
#endif
#include <linux/uidgid.h>

static struct kmem_cache *cred_jar;

/* init to 2 - one for init_task, one to ensure it is never freed */
static struct group_info init_groups = { .usage = ATOMIC_INIT(2) };

/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
    .usage          = ATOMIC_INIT(4),
    .uid            = GLOBAL_ROOT_UID,
    .gid            = GLOBAL_ROOT_GID,
    .suid           = GLOBAL_ROOT_UID,
    .sgid           = GLOBAL_ROOT_GID,
    .euid           = GLOBAL_ROOT_UID,
    .egid           = GLOBAL_ROOT_GID,
    .fsuid          = GLOBAL_ROOT_UID,
    .fsgid          = GLOBAL_ROOT_GID,
#if 0
    .securebits     = SECUREBITS_DEFAULT,
    .cap_inheritable    = CAP_EMPTY_SET,
    .cap_permitted      = CAP_FULL_SET,
    .cap_effective      = CAP_FULL_SET,
    .cap_bset       = CAP_FULL_SET,
#endif
    .user           = INIT_USER,
    .user_ns        = &init_user_ns,
    .group_info     = &init_groups,
    .ucounts        = &init_ucounts,
};

/**
 * abort_creds - Discard a set of credentials and unlock the current task
 * @new: The credentials that were going to be applied
 *
 * Discard a set of credentials that were under construction and unlock the
 * current task.
 */
void abort_creds(struct cred *new)
{
    pr_info("abort_creds(%p{%d})\n",
            new,
            atomic_read(&new->usage));

    BUG_ON(atomic_read(&new->usage) < 1);
    put_cred(new);
}
EXPORT_SYMBOL(abort_creds);

/*
 * The RCU callback to actually dispose of a set of credentials
 */
static void put_cred_rcu(struct rcu_head *rcu)
{
    panic("%s: END!\n", __func__);
}

/**
 * __put_cred - Destroy a set of credentials
 * @cred: The record to release
 *
 * Destroy a set of credentials on which no references remain.
 */
void __put_cred(struct cred *cred)
{
    pr_info("__put_cred(%p{%d})\n",
            cred,
            atomic_read(&cred->usage));

    BUG_ON(atomic_read(&cred->usage) != 0);
    BUG_ON(cred == current->cred);
    BUG_ON(cred == current->real_cred);

    if (cred->non_rcu)
        put_cred_rcu(&cred->rcu);
    else
        call_rcu(&cred->rcu, put_cred_rcu);
}
EXPORT_SYMBOL(__put_cred);

/**
 * prepare_creds - Prepare a new set of credentials for modification
 *
 * Prepare a new set of task credentials for modification.  A task's creds
 * shouldn't generally be modified directly, therefore this function is used to
 * prepare a new copy, which the caller then modifies and then commits by
 * calling commit_creds().
 *
 * Preparation involves making a copy of the objective creds for modification.
 *
 * Returns a pointer to the new creds-to-be if successful, NULL otherwise.
 *
 * Call commit_creds() or abort_creds() to clean up.
 */
struct cred *prepare_creds(void)
{
    struct task_struct *task = current;
    const struct cred *old;
    struct cred *new;

    new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
    if (!new)
        return NULL;

    pr_info("prepare_creds() alloc %p\n", new);

    old = task->cred;
    memcpy(new, old, sizeof(struct cred));

    new->non_rcu = 0;
    atomic_set(&new->usage, 1);
    get_group_info(new->group_info);
    get_uid(new->user);
    get_user_ns(new->user_ns);

#if 0
    key_get(new->session_keyring);
    key_get(new->process_keyring);
    key_get(new->thread_keyring);
    key_get(new->request_key_auth);
#endif

    new->ucounts = get_ucounts(new->ucounts);
    if (!new->ucounts)
        goto error;

    return new;

error:
    abort_creds(new);
    return NULL;
}

/*
 * Prepare credentials for current to perform an execve()
 * - The caller must hold ->cred_guard_mutex
 */
struct cred *prepare_exec_creds(void)
{
    struct cred *new;

    new = prepare_creds();
    if (!new)
        return new;

#if 0
    /* newly exec'd tasks don't get a thread keyring */
    key_put(new->thread_keyring);
    new->thread_keyring = NULL;

    /* inherit the session keyring; new process keyring */
    key_put(new->process_keyring);
    new->process_keyring = NULL;
#endif

    new->suid = new->fsuid = new->euid;
    new->sgid = new->fsgid = new->egid;

    return new;
}

/*
 * initialise the credentials stuff
 */
void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar =
        kmem_cache_create("cred_jar", sizeof(struct cred), 0,
                          SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
}
