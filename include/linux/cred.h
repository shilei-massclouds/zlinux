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

#endif /* _LINUX_CRED_H */
