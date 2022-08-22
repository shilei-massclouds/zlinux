/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMEKEEPING_H
#define _LINUX_TIMEKEEPING_H

#include <linux/errno.h>
#include <linux/clocksource_ids.h>

/* Included from linux/ktime.h */

void timekeeping_init(void);

extern ktime_t ktime_get(void);

#endif /* _LINUX_TIMEKEEPING_H */
