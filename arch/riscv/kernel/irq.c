// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2018 Christoph Hellwig
 */

#if 0
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#endif
#include <linux/irqchip.h>
#include <asm/smp.h>

void __init init_IRQ(void)
{
    irqchip_init();
    if (!handle_arch_irq)
        panic("No interrupt controller found.");
}
