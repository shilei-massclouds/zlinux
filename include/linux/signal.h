/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIGNAL_H
#define _LINUX_SIGNAL_H

#include <linux/bug.h>
#include <linux/signal_types.h>
#include <linux/string.h>

struct task_struct;

static inline void sigemptyset(sigset_t *set)
{
    switch (_NSIG_WORDS) {
    default:
        memset(set, 0, sizeof(sigset_t));
        break;
    case 2: set->sig[1] = 0;
        fallthrough;
    case 1: set->sig[0] = 0;
        break;
    }
}

void signals_init(void);

#endif /* _LINUX_SIGNAL_H */
