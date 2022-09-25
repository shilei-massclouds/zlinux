// SPDX-License-Identifier: GPL-2.0
/*
 * Tty buffer allocation management
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
//#include <linux/tty_flip.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include "tty.h"

/*
 * Byte threshold to limit memory consumption for flip buffers.
 * The actual memory limit is > 2x this amount.
 */
#define TTYB_DEFAULT_MEM_LIMIT  (640 * 1024UL)

static void tty_buffer_reset(struct tty_buffer *p, size_t size)
{
    p->used = 0;
    p->size = size;
    p->next = NULL;
    p->commit = 0;
    p->read = 0;
    p->flags = 0;
}

/**
 * flush_to_ldisc       -   flush data from buffer to ldisc
 * @work: tty structure passed from work queue.
 *
 * This routine is called out of the software interrupt to flush data from the
 * buffer chain to the line discipline.
 *
 * The receive_buf() method is single threaded for each tty instance.
 *
 * Locking: takes buffer lock to ensure single-threaded flip buffer 'consumer'.
 */
static void flush_to_ldisc(struct work_struct *work)
{
    panic("%s: END!\n", __func__);
}

/**
 * tty_buffer_init      -   prepare a tty buffer structure
 * @port: tty port to initialise
 *
 * Set up the initial state of the buffer management for a tty device. Must be
 * called before the other tty buffer functions are used.
 */
void tty_buffer_init(struct tty_port *port)
{
    struct tty_bufhead *buf = &port->buf;

    mutex_init(&buf->lock);
    tty_buffer_reset(&buf->sentinel, 0);
    buf->head = &buf->sentinel;
    buf->tail = &buf->sentinel;
    init_llist_head(&buf->free);
    atomic_set(&buf->mem_used, 0);
    atomic_set(&buf->priority, 0);
    INIT_WORK(&buf->work, flush_to_ldisc);
    buf->mem_limit = TTYB_DEFAULT_MEM_LIMIT;
}
