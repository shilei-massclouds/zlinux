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

#endif /* _LINUX_RANDOM_H */
