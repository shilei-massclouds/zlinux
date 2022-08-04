/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/ratelimit_types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

static inline void
ratelimit_set_flags(struct ratelimit_state *rs, unsigned long flags)
{
    rs->flags = flags;
}

#endif /* _LINUX_RATELIMIT_H */
