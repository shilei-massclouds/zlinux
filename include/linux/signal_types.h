/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIGNAL_TYPES_H
#define _LINUX_SIGNAL_TYPES_H

/*
 * Basic signal handling related data type definitions:
 */

#include <linux/list.h>
#include <uapi/linux/signal.h>

struct sigpending {
    struct list_head list;
    sigset_t signal;
};

struct sigaction {
    __sighandler_t  sa_handler;
    unsigned long   sa_flags;
    sigset_t        sa_mask;    /* mask last for extensibility */
};

struct k_sigaction {
    struct sigaction sa;
};

#endif /* _LINUX_SIGNAL_TYPES_H */
