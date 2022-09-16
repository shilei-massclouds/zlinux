// SPDX-License-Identifier: GPL-2.0-only
/*
 * ratelimit.c - Do something with rate limit.
 *
 * Isolated from kernel/printk.c by Dave Young <hidave.darkstar@gmail.com>
 *
 * 2008-05-01 rewrite the function and use a ratelimit_state data struct as
 * parameter. Now every user can use their own standalone ratelimit_state.
 */

#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <linux/export.h>

/*
 * __ratelimit - rate limiting
 * @rs: ratelimit_state data
 * @func: name of calling function
 *
 * This enforces a rate limit: not more than @rs->burst callbacks
 * in every @rs->interval
 *
 * RETURNS:
 * 0 means callbacks will be suppressed.
 * 1 means go ahead and do it.
 */
int ___ratelimit(struct ratelimit_state *rs, const char *func)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(___ratelimit);
