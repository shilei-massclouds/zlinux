/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/compiler.h>

void panic(const char *fmt, ...) __noreturn __cold;

#endif /* _LINUX_KERNEL_H */
