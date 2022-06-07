// SPDX-License-Identifier: GPL-2.0
/*
 * dev_printk.h - printk messages helpers for devices
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 */

#ifndef _DEVICE_PRINTK_H_
#define _DEVICE_PRINTK_H_

#include <linux/compiler.h>
#include <linux/types.h>
//#include <linux/ratelimit.h>

#ifndef dev_fmt
#define dev_fmt(fmt) fmt
#endif

struct device;

#define PRINTK_INFO_SUBSYSTEM_LEN   16
#define PRINTK_INFO_DEVICE_LEN      48

struct dev_printk_info {
    char subsystem[PRINTK_INFO_SUBSYSTEM_LEN];
    char device[PRINTK_INFO_DEVICE_LEN];
};

#endif /* _DEVICE_PRINTK_H_ */
