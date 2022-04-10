// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/init.h>

/*
 * This is called extremly early, before parse_dtb(), to allow initializing
 * SoC hardware before memory or any device driver initialization.
 */
void __init soc_early_init(void)
{
}
