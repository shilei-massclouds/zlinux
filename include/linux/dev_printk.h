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
#include <linux/ratelimit.h>

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

static inline __printf(2, 3)
void _dev_err(const struct device *dev, const char *fmt, ...)
{}

static inline __printf(2, 3)
void _dev_warn(const struct device *dev, const char *fmt, ...)
{}

/*
 * Need to take variadic arguments even though we don't use them, as dev_fmt()
 * may only just have been expanded and may result in multiple arguments.
 */
#define dev_printk_index_emit(level, fmt, ...) \
    printk_index_subsys_emit("%s %s: ", level, fmt)

#define dev_printk_index_wrap(_p_func, level, dev, fmt, ...)        \
    ({                              \
        dev_printk_index_emit(level, fmt);          \
        _p_func(dev, fmt, ##__VA_ARGS__);           \
    })

#define dev_err(dev, fmt, ...) \
    dev_printk_index_wrap(_dev_err, KERN_ERR, dev, dev_fmt(fmt), \
                          ##__VA_ARGS__)

#define dev_warn(dev, fmt, ...) \
    dev_printk_index_wrap(_dev_warn, KERN_WARNING, dev, dev_fmt(fmt), \
                          ##__VA_ARGS__)

#define dev_dbg(dev, fmt, ...)

#endif /* _DEVICE_PRINTK_H_ */
