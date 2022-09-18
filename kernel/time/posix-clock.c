// SPDX-License-Identifier: GPL-2.0+
/*
 * Support for dynamic clock devices
 *
 * Copyright (C) 2010 OMICRON electronics GmbH
 */
#include <linux/device.h>
#include <linux/export.h>
#include <linux/file.h>
//#include <linux/posix-clock.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

//#include "posix-timers.h"
