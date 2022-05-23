// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/bitops.h>
#include <asm/types.h>

unsigned long __sw_hweight64(__u64 w)
{
    __u64 res = w - ((w >> 1) & 0x5555555555555555ul);
    res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
    res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
    res = res + (res >> 8);
    res = res + (res >> 16);
    return (res + (res >> 32)) & 0x00000000000000FFul;
}
EXPORT_SYMBOL(__sw_hweight64);
