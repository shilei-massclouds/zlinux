/*
 * Copyright (C) 2012 Thomas Petazzoni
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#if 0
#include <linux/acpi.h>
#endif
#include <linux/init.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/irqchip.h>
#include <linux/platform_device.h>

extern struct of_device_id __irqchip_of_table[];

void __init irqchip_init(void)
{
    of_irq_init(__irqchip_of_table);
}
