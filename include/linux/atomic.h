/* SPDX-License-Identifier: GPL-2.0 */
/* Atomic operations usable in machine independent code */
#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H

#include <linux/types.h>

#include <asm/atomic.h>
//#include <asm/barrier.h>

/* End */

#include <linux/atomic/atomic-arch-fallback.h>
#include <linux/atomic/atomic-long.h>
#include <linux/atomic/atomic-instrumented.h>

#endif /* _LINUX_ATOMIC_H */
