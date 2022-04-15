// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/export.h>

asmlinkage __visible int printk(const char *fmt, ...)
{
    /*
    va_list args;
    int r;

    va_start(args, fmt);
    r = vprintk_func(fmt, args);
    va_end(args);

    return r;
    */
    return 0;
}
EXPORT_SYMBOL(printk);
