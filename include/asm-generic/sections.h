/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_SECTIONS_H_
#define _ASM_GENERIC_SECTIONS_H_

/* References to section boundaries */

#include <linux/compiler.h>
#include <linux/types.h>

extern char _start[], _end[];
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];

#endif /* _ASM_GENERIC_SECTIONS_H_ */
