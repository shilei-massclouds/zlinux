// SPDX-License-Identifier: GPL-1.0+
/*
 * n_tty.c --- implements the N_TTY line discipline.
 *
 * This code used to be in tty_io.c, but things are getting hairy
 * enough that it made sense to split things off.  (The N_TTY
 * processing has changed so much that it's hardly recognizable,
 * anyway...)
 *
 * Note that the open routine for N_TTY is guaranteed never to return
 * an error.  This is because Linux will fall back to setting a line
 * to N_TTY if it can not switch to any other line discipline.
 *
 * Written by Theodore Ts'o, Copyright 1994.
 *
 * This file also contains code originally written by Linus Torvalds,
 * Copyright 1991, 1992, 1993, and by Julian Cowley, Copyright 1994.
 *
 * Reduced memory usage for older ARM systems  - Russell King.
 *
 * 2000/01/20   Fixed SMP locking on put_tty_queue using bits of
 *      the patch by Andrew J. Kroll <ag784@freenet.buffalo.edu>
 *      who actually finally proved there really was a race.
 *
 * 2002/03/18   Implemented n_tty_wakeup to send SIGIO POLL_OUTs to
 *      waiting writing processes-Sapan Bhatia <sapan@corewars.org>.
 *      Also fixed a bug in BLOCKING mode where n_tty_write returns
 *      EAGAIN
 */

#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/bitops.h>
//#include <linux/audit.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/tty_ldisc.h>
#include "tty.h"

/**
 * n_tty_open       -   open an ldisc
 * @tty: terminal to open
 *
 * Called when this line discipline is being attached to the terminal device.
 * Can sleep. Called serialized so that no other events will occur in parallel.
 * No further open will occur until a close.
 */
static int n_tty_open(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_close      -   close the ldisc for this tty
 * @tty: device
 *
 * Called from the terminal layer when this line discipline is being shut down,
 * either because of a close or becsuse of a discipline change. The function
 * will not be called while other ldisc methods are in progress.
 */
static void n_tty_close(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/**
 * reset_buffer_flags   -   reset buffer state
 * @ldata: line disc data to reset
 *
 * Reset the read buffer counters and clear the flags. Called from
 * n_tty_open() and n_tty_flush_buffer().
 *
 * Locking:
 *  * caller holds exclusive %termios_rwsem, or
 *  * (locking is not required)
 */
static void reset_buffer_flags(struct n_tty_data *ldata)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_kick_worker - start input worker (if required)
 * @tty: terminal
 *
 * Re-schedules the flip buffer work if it may have stopped.
 *
 * Locking:
 *  * Caller holds exclusive %termios_rwsem, or
 *  * n_tty_read()/consumer path:
 *  holds non-exclusive %termios_rwsem
 */
static void n_tty_kick_worker(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_write      -   write function for tty
 * @tty: tty device
 * @file: file object
 * @buf: userspace buffer pointer
 * @nr: size of I/O
 *
 * Write function of the terminal device. This is serialized with respect to
 * other write callers but not to termios changes, reads and other such events.
 * Since the receive code will echo characters, thus calling driver write
 * methods, the %output_lock is used in the output processing functions called
 * here as well as in the echo processing function to protect the column state
 * and space left in the buffer.
 *
 * This code must be sure never to sleep through a hangup.
 *
 * Locking: output_lock to protect column state and space left
 *   (note that the process_output*() functions take this lock themselves)
 */
static ssize_t n_tty_write(struct tty_struct *tty, struct file *file,
                           const unsigned char *buf, size_t nr)
{
    panic("%s: END!\n", __func__);
}

static int n_tty_ioctl(struct tty_struct *tty, unsigned int cmd,
                       unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_set_termios    -   termios data changed
 * @tty: terminal
 * @old: previous data
 *
 * Called by the tty layer when the user changes termios flags so that the line
 * discipline can plan ahead. This function cannot sleep and is protected from
 * re-entry by the tty layer. The user is guaranteed that this function will
 * not be re-entered or in progress when the ldisc is closed.
 *
 * Locking: Caller holds @tty->termios_rwsem
 */
static void n_tty_set_termios(struct tty_struct *tty,
                              struct ktermios *old)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_receive_buf_common -   process input
 * @tty: device to receive input
 * @cp: input chars
 * @fp: flags for each char (if %NULL, all chars are %TTY_NORMAL)
 * @count: number of input chars in @cp
 * @flow: enable flow control
 *
 * Called by the terminal driver when a block of characters has been received.
 * This function must be called from soft contexts not from interrupt context.
 * The driver is responsible for making calls one at a time and in order (or
 * using flush_to_ldisc()).
 *
 * Returns: the # of input chars from @cp which were processed.
 *
 * In canonical mode, the maximum line length is 4096 chars (including the line
 * termination char); lines longer than 4096 chars are truncated. After 4095
 * chars, input data is still processed but not stored. Overflow processing
 * ensures the tty can always receive more input until at least one line can be
 * read.
 *
 * In non-canonical mode, the read buffer will only accept 4095 chars; this
 * provides the necessary space for a newline char if the input mode is
 * switched to canonical.
 *
 * Note it is possible for the read buffer to _contain_ 4096 chars in
 * non-canonical mode: the read buffer could already contain the maximum canon
 * line of 4096 chars when the mode is switched to non-canonical.
 *
 * Locking: n_tty_receive_buf()/producer path:
 *  claims non-exclusive %termios_rwsem
 *  publishes commit_head or canon_head
 */
static int
n_tty_receive_buf_common(struct tty_struct *tty,
                         const unsigned char *cp,
                         const char *fp, int count, int flow)
{
    panic("%s: END!\n", __func__);
}

static void n_tty_receive_buf(struct tty_struct *tty,
                              const unsigned char *cp,
                              const char *fp, int count)
{
    n_tty_receive_buf_common(tty, cp, fp, count, 0);
}

static int n_tty_receive_buf2(struct tty_struct *tty,
                              const unsigned char *cp,
                              const char *fp, int count)
{
    return n_tty_receive_buf_common(tty, cp, fp, count, 1);
}

/**
 * n_tty_flush_buffer   -   clean input queue
 * @tty: terminal device
 *
 * Flush the input buffer. Called when the tty layer wants the buffer flushed
 * (eg at hangup) or when the %N_TTY line discipline internally has to clean
 * the pending queue (for example some signals).
 *
 * Holds %termios_rwsem to exclude producer/consumer while buffer indices are
 * reset.
 *
 * Locking: %ctrl.lock, exclusive %termios_rwsem
 */
static void n_tty_flush_buffer(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_read       -   read function for tty
 * @tty: tty device
 * @file: file object
 * @kbuf: kernelspace buffer pointer
 * @nr: size of I/O
 * @cookie: if non-%NULL, this is a continuation read
 * @offset: where to continue reading from (unused in n_tty)
 *
 * Perform reads for the line discipline. We are guaranteed that the line
 * discipline will not be closed under us but we may get multiple parallel
 * readers and must handle this ourselves. We may also get a hangup. Always
 * called in user context, may sleep.
 *
 * This code must be sure never to sleep through a hangup.
 *
 * Locking: n_tty_read()/consumer path:
 *  claims non-exclusive termios_rwsem;
 *  publishes read_tail
 */
static ssize_t
n_tty_read(struct tty_struct *tty, struct file *file,
           unsigned char *kbuf, size_t nr,
           void **cookie, unsigned long offset)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_poll       -   poll method for N_TTY
 * @tty: terminal device
 * @file: file accessing it
 * @wait: poll table
 *
 * Called when the line discipline is asked to poll() for data or for special
 * events. This code is not serialized with respect to other events save
 * open/close.
 *
 * This code must be sure never to sleep through a hangup.
 *
 * Locking: called without the kernel lock held -- fine.
 */
static __poll_t n_tty_poll(struct tty_struct *tty, struct file *file,
                            poll_table *wait)
{
    panic("%s: END!\n", __func__);
}

/**
 * n_tty_write_wakeup   -   asynchronous I/O notifier
 * @tty: tty device
 *
 * Required for the ptys, serial driver etc. since processes that attach
 * themselves to the master and rely on ASYNC IO must be woken up.
 */
static void n_tty_write_wakeup(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static struct tty_ldisc_ops n_tty_ops = {
    .owner       = THIS_MODULE,
    .num         = N_TTY,
    .name            = "n_tty",
    .open            = n_tty_open,
    .close           = n_tty_close,
    .flush_buffer    = n_tty_flush_buffer,
    .read            = n_tty_read,
    .write           = n_tty_write,
    .ioctl           = n_tty_ioctl,
    .set_termios     = n_tty_set_termios,
    .poll            = n_tty_poll,
    .receive_buf     = n_tty_receive_buf,
    .write_wakeup    = n_tty_write_wakeup,
    .receive_buf2    = n_tty_receive_buf2,
};

void __init n_tty_init(void)
{
    tty_register_ldisc(&n_tty_ops);
}
