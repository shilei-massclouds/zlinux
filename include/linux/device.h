// SPDX-License-Identifier: GPL-2.0
/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <linux/list.h>
#if 0
#include <linux/dev_printk.h>
#include <linux/energy_model.h>
#include <linux/ioport.h>
#include <linux/kobject.h>
#include <linux/klist.h>
#include <linux/lockdep.h>
#include <linux/compiler.h>
#endif
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/gfp.h>
#if 0
#include <linux/pm.h>
#include <linux/uidgid.h>
#include <linux/overflow.h>
#include <linux/device/bus.h>
#include <linux/device/class.h>
#include <linux/device/driver.h>
#include <asm/device.h>
#endif

struct device {
    void (*release)(struct device *dev);
};

void device_initialize(struct device *dev);

#endif /* _DEVICE_H_ */
