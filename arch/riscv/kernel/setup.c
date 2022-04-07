// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/types.h>

/*
 * The lucky hart to first increment this variable
 * will boot the other cores.
 * This is used before the kernel initializes the BSS
 * so it can't be in the BSS.
 */
atomic_t hart_lottery __section(.sdata);
unsigned long boot_cpu_hartid;
