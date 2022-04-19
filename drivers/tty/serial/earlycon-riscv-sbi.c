// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V SBI based earlycon
 *
 * Copyright (C) 2018 Anup Patel <anup@brainfault.org>
 */
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/serial_core.h>
//#include <asm/sbi.h>

static int __init
early_sbi_setup(struct earlycon_device *device, const char *opt)
{
    //device->con->write = sbi_console_write;
    return 0;
}
EARLYCON_DECLARE(sbi, early_sbi_setup);
