/*
 * Copyright (C) 2012 Thomas Petazzoni
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _LINUX_IRQCHIP_H
#define _LINUX_IRQCHIP_H

#if 0
#include <linux/acpi.h>
#endif
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

void irqchip_init(void);

#endif /* _LINUX_IRQCHIP_H */
