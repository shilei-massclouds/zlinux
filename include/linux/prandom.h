/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/prandom.h
 *
 * Include file for the fast pseudo-random 32-bit
 * generation.
 */
#ifndef _LINUX_PRANDOM_H
#define _LINUX_PRANDOM_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/siphash.h>

u32 prandom_u32(void);

/*
 * The core SipHash round function.  Each line can be executed in
 * parallel given enough CPU resources.
 */
#define PRND_SIPROUND(v0, v1, v2, v3) SIPHASH_PERMUTATION(v0, v1, v2, v3)

#endif /* _LINUX_PRANDOM_H */
