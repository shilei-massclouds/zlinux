/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_BUFFER_H
#define _LINUX_TTY_BUFFER_H

#include <linux/atomic.h>
#include <linux/llist.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

struct tty_buffer {
    union {
        struct tty_buffer *next;
        struct llist_node free;
    };
    int used;
    int size;
    int commit;
    int read;
    int flags;
    /* Data points here */
    unsigned long data[];
};

struct tty_bufhead {
    struct tty_buffer *head;    /* Queue head */
    struct work_struct work;
    struct mutex       lock;
    atomic_t       priority;
    struct tty_buffer sentinel;
    struct llist_head free;     /* Free queue head */
    atomic_t       mem_used;    /* In-use buffers excluding free list */
    int        mem_limit;
    struct tty_buffer *tail;    /* Active buffer */
};

#endif /* _LINUX_TTY_BUFFER_H */
