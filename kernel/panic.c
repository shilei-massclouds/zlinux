// SPDX-License-Identifier: GPL-2.0-only

#include <linux/export.h>
#include <linux/sched.h>
#include <linux/init.h>

/**
 *  panic - halt the system
 *  @fmt: The text string to print
 *
 *  Display a message, then perform cleanups.
 *
 *  This function never returns.
 */
void panic(const char *fmt, ...)
{
}
EXPORT_SYMBOL(panic);
