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

#ifdef CONFIG_STACKPROTECTOR
/*
 * Called when gcc's -fstack-protector feature is used, and
 * gcc detects corruption of the on-stack canary value
 */
__visible noinstr void __stack_chk_fail(void)
{
    panic("stack-protector: Kernel stack is corrupted in: %pB",
          __builtin_return_address(0));
}
EXPORT_SYMBOL(__stack_chk_fail);
#endif
