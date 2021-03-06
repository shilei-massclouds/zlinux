// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/reboot.h>
#include <linux/pm.h>

static void default_power_off(void)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    while (1)
        wait_for_interrupt();
#endif
}

void (*pm_power_off)(void) = NULL;
EXPORT_SYMBOL(pm_power_off);

void machine_halt(void)
{
    if (pm_power_off != NULL)
        pm_power_off();
    else
        default_power_off();
}

void machine_power_off(void)
{
    if (pm_power_off != NULL)
        pm_power_off();
    else
        default_power_off();
}
