/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_LDISC_H
#define _LINUX_TTY_LDISC_H

struct tty_struct;

#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/lockdep.h>
//#include <linux/seq_file.h>

/*
 * the semaphore definition
 */
struct ld_semaphore {
    atomic_long_t       count;
    raw_spinlock_t      wait_lock;
    unsigned int        wait_readers;
    struct list_head    read_wait;
    struct list_head    write_wait;
};

#endif /* _LINUX_TTY_LDISC_H */
