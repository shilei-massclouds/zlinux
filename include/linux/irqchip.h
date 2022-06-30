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

/* Undefined on purpose */
extern of_irq_init_cb_t typecheck_irq_init_cb;

#define typecheck_irq_init_cb(fn) \
    (__typecheck(typecheck_irq_init_cb, &fn) ? fn : fn)

/*
 * This macro must be used by the different irqchip drivers to declare
 * the association between their DT compatible string and their
 * initialization function.
 *
 * @name: name that must be unique across all IRQCHIP_DECLARE of the
 * same file.
 * @compat: compatible string of the irqchip driver
 * @fn: initialization function
 */
#define IRQCHIP_DECLARE(name, compat, fn)   \
    OF_DECLARE_2(irqchip, name, compat, typecheck_irq_init_cb(fn))

void irqchip_init(void);

#endif /* _LINUX_IRQCHIP_H */
