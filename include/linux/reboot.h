/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_REBOOT_H
#define _LINUX_REBOOT_H

#if 0
#include <linux/notifier.h>
#include <uapi/linux/reboot.h>
#endif

struct device;

/*
 * Architecture-specific implementations of sys_reboot commands.
 */

extern void machine_halt(void);
extern void machine_power_off(void);

#if 0
#include <asm/emergency-restart.h>
#endif

#endif /* _LINUX_REBOOT_H */
