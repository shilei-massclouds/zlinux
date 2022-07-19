/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Credentials management - see Documentation/security/credentials.rst
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_CRED_H
#define _LINUX_CRED_H

//#include <linux/capability.h>
#include <linux/init.h>
//#include <linux/key.h>
#include <linux/atomic.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
//#include <linux/sched/user.h>

struct cred;
struct inode;

extern struct user_namespace init_user_ns;

struct cred {
    atomic_t    usage;
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
#if 0
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;       /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
    unsigned char   jit_keyring;    /* default keyring to attach requested
                                     * keys to */
    struct key  *session_keyring;   /* keyring inherited over fork */
    struct key  *process_keyring;   /* keyring private to this process */
    struct key  *thread_keyring;    /* keyring private to this thread */
    struct key  *request_key_auth;  /* assumed request_key authority */
    struct user_struct *user;       /* real user ID subscription */
#endif
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are
                                       relative to. */
#if 0
    struct ucounts *ucounts;
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
#endif
    /* RCU deletion */
    union {
        int non_rcu;            /* Can we skip RCU deletion? */
        struct rcu_head rcu;        /* RCU deletion hook */
    };
} __randomize_layout;

/**
 * current_cred - Access the current task's subjective credentials
 *
 * Access the subjective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_cred() \
    rcu_dereference_protected(current->cred)

/**
 * get_current_cred - Get the current task's subjective credentials
 *
 * Get the subjective credentials of the current task, pinning them so that
 * they can't go away.  Accessing the current task's credentials directly is
 * not permitted.
 */
#define get_current_cred() \
    (get_cred(current_cred()))

/**
 * get_new_cred - Get a reference on a new set of credentials
 * @cred: The new credentials to reference
 *
 * Get a reference on the specified set of new credentials.  The caller must
 * release the reference.
 */
static inline struct cred *get_new_cred(struct cred *cred)
{
    atomic_inc(&cred->usage);
    return cred;
}

/**
 * get_cred - Get a reference on a set of credentials
 * @cred: The credentials to reference
 *
 * Get a reference on the specified set of credentials.  The caller must
 * release the reference.  If %NULL is passed, it is returned with no action.
 *
 * This is used to deal with a committed set of credentials.  Although the
 * pointer is const, this will temporarily discard the const and increment the
 * usage count.  The purpose of this is to attempt to catch at compile time the
 * accidental alteration of a set of credentials that should be considered
 * immutable.
 */
static inline const struct cred *get_cred(const struct cred *cred)
{
    struct cred *nonconst_cred = (struct cred *) cred;
    if (!cred)
        return cred;
    nonconst_cred->non_rcu = 0;
    return get_new_cred(nonconst_cred);
}

#define current_cred_xxx(xxx)   \
({                              \
    current_cred()->xxx;        \
})

#define current_uid()       (current_cred_xxx(uid))
#define current_gid()       (current_cred_xxx(gid))
#define current_euid()      (current_cred_xxx(euid))
#define current_egid()      (current_cred_xxx(egid))
#define current_suid()      (current_cred_xxx(suid))
#define current_sgid()      (current_cred_xxx(sgid))
#define current_fsuid()     (current_cred_xxx(fsuid))
#define current_fsgid()     (current_cred_xxx(fsgid))
#define current_cap()       (current_cred_xxx(cap_effective))
#define current_user()      (current_cred_xxx(user))
#define current_ucounts()   (current_cred_xxx(ucounts))

#endif /* _LINUX_CRED_H */
