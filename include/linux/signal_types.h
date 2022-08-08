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

#endif /* _LINUX_SIGNAL_TYPES_H */
