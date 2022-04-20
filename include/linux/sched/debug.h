/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_DEBUG_H
#define _LINUX_SCHED_DEBUG_H

/* Attach to any functions which should be ignored in wchan output. */
#define __sched     __attribute__((__section__(".sched.text")))

#endif /* _LINUX_SCHED_DEBUG_H */
