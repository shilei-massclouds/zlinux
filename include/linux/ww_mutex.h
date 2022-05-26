/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wound/Wait Mutexes: blocking mutual exclusion locks with deadlock avoidance
 *
 * Original mutex implementation started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * Wait/Die implementation:
 *  Copyright (C) 2013 Canonical Ltd.
 * Choice of algorithm:
 *  Copyright (C) 2018 WMWare Inc.
 *
 * This file contains the main data structure and API definitions.
 */

#ifndef __LINUX_WW_MUTEX_H
#define __LINUX_WW_MUTEX_H

#include <linux/mutex.h>
//#include <linux/rtmutex.h>

#define WW_MUTEX_BASE               mutex
#define ww_mutex_base_init(l,n,k)   __mutex_init(l,n,k)
#define ww_mutex_base_is_locked(b)  mutex_is_locked((b))

struct ww_mutex {
    struct WW_MUTEX_BASE base;
    struct ww_acquire_ctx *ctx;
};

struct ww_acquire_ctx {
    struct task_struct *task;
    unsigned long stamp;
    unsigned int acquired;
    unsigned short wounded;
    unsigned short is_wait_die;
};

#endif /* __LINUX_WW_MUTEX_H */
