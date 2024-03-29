// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
//#include <linux/fault-inject-usercopy.h>
//#include <linux/instrumented.h>
#include <linux/uaccess.h>

unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res = n;
    might_fault();
    if (likely(access_ok(from, n))) {
        res = raw_copy_from_user(to, from, n);
    }
    if (unlikely(res))
        memset(to + (n - res), 0, res);
    return res;
}
EXPORT_SYMBOL(_copy_from_user);

unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
    might_fault();
    if (likely(access_ok(to, n))) {
        n = raw_copy_to_user(to, from, n);
    }
    return n;
}
EXPORT_SYMBOL(_copy_to_user);
