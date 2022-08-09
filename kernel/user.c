// SPDX-License-Identifier: GPL-2.0-only
/*
 * The "user cache".
 *
 * (C) Copyright 1991-2000 Linus Torvalds
 *
 * We have a per-user structure to keep track of how many
 * processes, files etc the user has claimed, in order to be
 * able to have per-user limits for system resources.
 */

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#if 0
#include <linux/key.h>
#endif
#include <linux/sched/user.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/user_namespace.h>
//#include <linux/proc_ns.h>

/*
 * userns count is 1 for root user, 1 for init_uts_ns,
 * and 1 for... ?
 */
struct user_namespace init_user_ns = {
};
EXPORT_SYMBOL_GPL(init_user_ns);

/* root_user.__count is 1, for init task cred */
struct user_struct root_user = {
    .__count    = REFCOUNT_INIT(1),
    .uid        = GLOBAL_ROOT_UID,
    .ratelimit  = RATELIMIT_STATE_INIT(root_user.ratelimit, 0, 0),
};
