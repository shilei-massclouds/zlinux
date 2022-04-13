// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>

#include "head.h"

/*
 * C entry point for a secondary processor.
 */
asmlinkage __visible void smp_callin(void)
{
    panic("%s: Not implement!\n", __func__);
}
