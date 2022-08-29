/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/list.h>
#if 0
#include <linux/once.h>

#include <uapi/linux/random.h>
#endif

/*
 * This is designed to be standalone for just prandom
 * users, but for now we include it from <linux/random.h>
 * for legacy reasons.
 */
#include <linux/prandom.h>

u64 get_random_u64(void);

static inline unsigned long get_random_long(void)
{
    //return get_random_u64();
    panic("%s: END!\n", __func__);
}

#endif /* _LINUX_RANDOM_H */
