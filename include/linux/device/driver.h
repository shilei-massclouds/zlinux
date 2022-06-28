// SPDX-License-Identifier: GPL-2.0
/*
 * The driver-specific portions of the driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 * Copyright (c) 2012-2019 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2012-2019 Linux Foundation
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_DRIVER_H_
#define _DEVICE_DRIVER_H_

#include <linux/kobject.h>
#include <linux/klist.h>
#if 0
#include <linux/pm.h>
#endif
#include <linux/device/bus.h>
#include <linux/module.h>

void driver_init(void);

#endif  /* _DEVICE_DRIVER_H_ */
