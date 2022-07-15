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
#if 0
#include <linux/sched/coredump.h>
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
    .user           = INIT_USER,
#endif
    .user_ns        = &init_user_ns,
#if 0
    .group_info     = &init_groups,
    .ucounts        = &init_ucounts,
#endif
};
