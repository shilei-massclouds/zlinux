/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/init.h>
#include <linux/linkage.h>

__HEAD
ENTRY(_start)
	j _start_kernel

__INIT
ENTRY(_start_kernel)
    sbreak
