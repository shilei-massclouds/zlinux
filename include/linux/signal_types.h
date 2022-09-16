/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIGNAL_TYPES_H
#define _LINUX_SIGNAL_TYPES_H

/*
 * Basic signal handling related data type definitions:
 */

#include <linux/list.h>
#include <uapi/linux/signal.h>

typedef struct kernel_siginfo {
    __SIGINFO;
} kernel_siginfo_t;

struct ucounts;

/*
 * Real Time signals may be queued.
 */

struct sigqueue {
    struct list_head list;
    int flags;
    kernel_siginfo_t info;
    struct ucounts *ucounts;
};

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

struct ksignal {
    struct k_sigaction ka;
    kernel_siginfo_t info;
    int sig;
};

/* Used to kill the race between sigaction and forced signals */
#define SA_IMMUTABLE        0x00800000

#endif /* _LINUX_SIGNAL_TYPES_H */
