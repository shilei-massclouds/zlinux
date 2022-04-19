/* SPDX-License-Identifier: GPL-2.0 */
/* Atomic operations usable in machine independent code */
#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H

#include <linux/types.h>

#include <asm/atomic.h>
//#include <asm/barrier.h>

/* End */

#include <linux/atomic-fallback.h>
#include <asm-generic/atomic-long.h>

#endif /* _LINUX_ATOMIC_H */
