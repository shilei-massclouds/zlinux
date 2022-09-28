/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RATELIMIT_H
#define _LINUX_RATELIMIT_H

#include <linux/ratelimit_types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#define WARN_RATELIMIT(condition, format, ...)          \
({                              \
    static DEFINE_RATELIMIT_STATE(_rs,          \
                      DEFAULT_RATELIMIT_INTERVAL,   \
                      DEFAULT_RATELIMIT_BURST); \
    int rtn = !!(condition);                \
                                \
    if (unlikely(rtn && __ratelimit(&_rs)))         \
        WARN(rtn, format, ##__VA_ARGS__);       \
                                \
    rtn;                            \
})

static inline void
ratelimit_set_flags(struct ratelimit_state *rs, unsigned long flags)
{
    rs->flags = flags;
}

#endif /* _LINUX_RATELIMIT_H */
