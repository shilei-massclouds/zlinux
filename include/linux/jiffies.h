/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <linux/cache.h>
#include <linux/limits.h>
//#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/types.h>
/*
#include <linux/time.h>
#include <linux/timex.h>
#include <vdso/jiffies.h>
*/
#include <asm/param.h>          /* for HZ */
//#include <generated/timeconst.h>

/*
 * Have the 32 bit jiffies value wrap 5 minutes after boot
 * so jiffies wrap bugs show up earlier.
 */
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))

#ifndef __jiffy_arch_data
#define __jiffy_arch_data
#endif

/*
 * The 64-bit value is not atomic - you MUST NOT read it
 * without sampling the sequence number in jiffies_lock.
 * get_jiffies_64() will do this for you as appropriate.
 */
extern u64 __cacheline_aligned_in_smp jiffies_64;
extern unsigned long volatile __cacheline_aligned_in_smp __jiffy_arch_data jiffies;

#endif /* _LINUX_JIFFIES_H */
