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

struct n_tty_data {
    /* producer-published */
    size_t read_head;
    size_t commit_head;
    size_t canon_head;
    size_t echo_head;
    size_t echo_commit;
    size_t echo_mark;
    DECLARE_BITMAP(char_map, 256);

    /* private to n_tty_receive_overrun (single-threaded) */
    unsigned long overrun_time;
    int num_overrun;

    /* non-atomic */
    bool no_room;

    /* must hold exclusive termios_rwsem to reset these */
    unsigned char lnext:1, erasing:1, raw:1, real_raw:1, icanon:1;
    unsigned char push:1;

    /* shared by producer and consumer */
    char read_buf[N_TTY_BUF_SIZE];
    DECLARE_BITMAP(read_flags, N_TTY_BUF_SIZE);
    unsigned char echo_buf[N_TTY_BUF_SIZE];

    /* consumer-published */
    size_t read_tail;
    size_t line_start;

    /* protected by output lock */
    unsigned int column;
    unsigned int canon_column;
    size_t echo_tail;

    struct mutex atomic_read_lock;
    struct mutex output_lock;
};

static inline size_t read_cnt(struct n_tty_data *ldata)
{
    return ldata->read_head - ldata->read_tail;
}

static void process_echoes(struct tty_struct *tty)
{
    struct n_tty_data *ldata = tty->disc_data;
    size_t echoed;

    if (ldata->echo_mark == ldata->echo_tail)
        return;

#if 0
    mutex_lock(&ldata->output_lock);
    ldata->echo_commit = ldata->echo_mark;
    echoed = __process_echoes(tty);
    mutex_unlock(&ldata->output_lock);

    if (echoed && tty->ops->flush_chars)
        tty->ops->flush_chars(tty);
#endif
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
    struct n_tty_data *ldata = tty->disc_data;

    if (!old ||
        (old->c_lflag ^ tty->termios.c_lflag) & (ICANON | EXTPROC)) {
        bitmap_zero(ldata->read_flags, N_TTY_BUF_SIZE);
        ldata->line_start = ldata->read_tail;
        if (!L_ICANON(tty) || !read_cnt(ldata)) {
            ldata->canon_head = ldata->read_tail;
            ldata->push = 0;
        } else {
            set_bit((ldata->read_head - 1) & (N_TTY_BUF_SIZE - 1),
                ldata->read_flags);
            ldata->canon_head = ldata->read_head;
            ldata->push = 1;
        }
        ldata->commit_head = ldata->read_head;
        ldata->erasing = 0;
        ldata->lnext = 0;
    }

    ldata->icanon = (L_ICANON(tty) != 0);

    if (I_ISTRIP(tty) || I_IUCLC(tty) || I_IGNCR(tty) ||
        I_ICRNL(tty) || I_INLCR(tty) || L_ICANON(tty) ||
        I_IXON(tty) || L_ISIG(tty) || L_ECHO(tty) ||
        I_PARMRK(tty)) {
        bitmap_zero(ldata->char_map, 256);

        if (I_IGNCR(tty) || I_ICRNL(tty))
            set_bit('\r', ldata->char_map);
        if (I_INLCR(tty))
            set_bit('\n', ldata->char_map);

        if (L_ICANON(tty)) {
            set_bit(ERASE_CHAR(tty), ldata->char_map);
            set_bit(KILL_CHAR(tty), ldata->char_map);
            set_bit(EOF_CHAR(tty), ldata->char_map);
            set_bit('\n', ldata->char_map);
            set_bit(EOL_CHAR(tty), ldata->char_map);
            if (L_IEXTEN(tty)) {
                set_bit(WERASE_CHAR(tty), ldata->char_map);
                set_bit(LNEXT_CHAR(tty), ldata->char_map);
                set_bit(EOL2_CHAR(tty), ldata->char_map);
                if (L_ECHO(tty))
                    set_bit(REPRINT_CHAR(tty),
                        ldata->char_map);
            }
        }
        if (I_IXON(tty)) {
            set_bit(START_CHAR(tty), ldata->char_map);
            set_bit(STOP_CHAR(tty), ldata->char_map);
        }
        if (L_ISIG(tty)) {
            set_bit(INTR_CHAR(tty), ldata->char_map);
            set_bit(QUIT_CHAR(tty), ldata->char_map);
            set_bit(SUSP_CHAR(tty), ldata->char_map);
        }
        clear_bit(__DISABLED_CHAR, ldata->char_map);
        ldata->raw = 0;
        ldata->real_raw = 0;
    } else {
        panic("%s: 2!\n", __func__);
    }
    /*
     * Fix tty hang when I_IXON(tty) is cleared, but the tty
     * been stopped by STOP_CHAR(tty) before it.
     */
    if (!I_IXON(tty) && old && (old->c_iflag & IXON) && !tty->flow.tco_stopped) {
        start_tty(tty);
        process_echoes(tty);
    }

    /* The termios change make the tty ready for I/O */
    wake_up_interruptible(&tty->write_wait);
    wake_up_interruptible(&tty->read_wait);
}

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
    struct n_tty_data *ldata;

    /* Currently a malloc failure here can panic */
    ldata = vzalloc(sizeof(*ldata));
    if (!ldata)
        return -ENOMEM;

    ldata->overrun_time = jiffies;
    mutex_init(&ldata->atomic_read_lock);
    mutex_init(&ldata->output_lock);

    tty->disc_data = ldata;
    tty->closing = 0;
    /* indicate buffer work may resume */
    clear_bit(TTY_LDISC_HALTED, &tty->flags);
    n_tty_set_termios(tty, NULL);
    tty_unthrottle(tty);
    return 0;
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
 * do_output_char   -   output one character
 * @c: character (or partial unicode symbol)
 * @tty: terminal device
 * @space: space available in tty driver write buffer
 *
 * This is a helper function that handles one output character (including
 * special characters like TAB, CR, LF, etc.), doing OPOST processing and
 * putting the results in the tty driver's write buffer.
 *
 * Note that Linux currently ignores TABDLY, CRDLY, VTDLY, FFDLY and NLDLY.
 * They simply aren't relevant in the world today. If you ever need them, add
 * them here.
 *
 * Returns: the number of bytes of buffer space used or -1 if no space left.
 *
 * Locking: should be called under the %output_lock to protect the column state
 * and space left in the buffer.
 */
static int do_output_char(unsigned char c, struct tty_struct *tty, int space)
{
    struct n_tty_data *ldata = tty->disc_data;
    int spaces;

    if (!space)
        return -1;

    panic("%s: END!\n", __func__);
}

/**
 * process_output   -   output post processor
 * @c: character (or partial unicode symbol)
 * @tty: terminal device
 *
 * Output one character with OPOST processing.
 *
 * Returns: -1 when the output device is full and the character must be
 * retried.
 *
 * Locking: %output_lock to protect column state and space left (also, this is
 *called from n_tty_write() under the tty layer write lock).
 */
static int process_output(unsigned char c, struct tty_struct *tty)
{
    struct n_tty_data *ldata = tty->disc_data;
    int space, retval;

    mutex_lock(&ldata->output_lock);

    space = tty_write_room(tty);
    retval = do_output_char(c, tty, space);

    mutex_unlock(&ldata->output_lock);
    if (retval < 0)
        return -1;
    else
        return 0;
}

/**
 * is_utf8_continuation -   utf8 multibyte check
 * @c: byte to check
 *
 * Returns: true if the utf8 character @c is a multibyte continuation
 * character. We use this to correctly compute the on-screen size of the
 * character when printing.
 */
static inline int is_utf8_continuation(unsigned char c)
{
    return (c & 0xc0) == 0x80;
}

/**
 * is_continuation  -   multibyte check
 * @c: byte to check
 * @tty: terminal device
 *
 * Returns: true if the utf8 character @c is a multibyte continuation character
 * and the terminal is in unicode mode.
 */
static inline
int is_continuation(unsigned char c, struct tty_struct *tty)
{
    return I_IUTF8(tty) && is_utf8_continuation(c);
}

/**
 * process_output_block -   block post processor
 * @tty: terminal device
 * @buf: character buffer
 * @nr: number of bytes to output
 *
 * Output a block of characters with OPOST processing.
 *
 * This path is used to speed up block console writes, among other things when
 * processing blocks of output data. It handles only the simple cases normally
 * found and helps to generate blocks of symbols for the console driver and
 * thus improve performance.
 *
 * Returns: the number of characters output.
 *
 * Locking: %output_lock to protect column state and space left (also, this is
 * called from n_tty_write() under the tty layer write lock).
 */
static ssize_t process_output_block(struct tty_struct *tty,
                                    const unsigned char *buf,
                                    unsigned int nr)
{
    struct n_tty_data *ldata = tty->disc_data;
    int space;
    int i;
    const unsigned char *cp;

    mutex_lock(&ldata->output_lock);

    space = tty_write_room(tty);
    if (space <= 0) {
        mutex_unlock(&ldata->output_lock);
        return space;
    }
    if (nr > space)
        nr = space;

    for (i = 0, cp = buf; i < nr; i++, cp++) {
        unsigned char c = *cp;

        switch (c) {
        case '\n':
            if (O_ONLRET(tty))
                ldata->column = 0;
            if (O_ONLCR(tty))
                goto break_out;
            ldata->canon_column = ldata->column;
            break;
        case '\r':
            if (O_ONOCR(tty) && ldata->column == 0)
                goto break_out;
            if (O_OCRNL(tty))
                goto break_out;
            ldata->canon_column = ldata->column = 0;
            break;
        case '\t':
            goto break_out;
        case '\b':
            if (ldata->column > 0)
                ldata->column--;
            break;
        default:
            if (!iscntrl(c)) {
                if (O_OLCUC(tty))
                    goto break_out;
                if (!is_continuation(c, tty))
                    ldata->column++;
            }
            break;
        }
    }

 break_out:
    i = tty->ops->write(tty, buf, i);

    mutex_unlock(&ldata->output_lock);
    return i;
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
    const unsigned char *b = buf;
    DEFINE_WAIT_FUNC(wait, woken_wake_function);
    int c;
    ssize_t retval = 0;

    /* Job control check -- must be done at start (POSIX.1 7.1.1.4). */
    if (L_TOSTOP(tty) &&
        file->f_op->write_iter != redirected_tty_write) {
        retval = tty_check_change(tty);
        if (retval)
            return retval;
    }

    down_read(&tty->termios_rwsem);

    /* Write out any echoed characters that are still pending */
    process_echoes(tty);

    add_wait_queue(&tty->write_wait, &wait);
    while (1) {
        if (signal_pending(current)) {
            retval = -ERESTARTSYS;
            break;
        }
        if (tty_hung_up_p(file) || (tty->link && !tty->link->count)) {
            retval = -EIO;
            break;
        }
        if (O_OPOST(tty)) {
            while (nr > 0) {
                ssize_t num = process_output_block(tty, b, nr);
                if (num < 0) {
                    if (num == -EAGAIN)
                        break;
                    retval = num;
                    goto break_out;
                }
                b += num;
                nr -= num;
                if (nr == 0)
                    break;
                c = *b;
                if (process_output(c, tty) < 0)
                    break;
                b++; nr--;
            }
            if (tty->ops->flush_chars)
                tty->ops->flush_chars(tty);
        } else {
            panic("%s: else O_OPOST!\n", __func__);
        }
        if (!nr)
            break;
        if (tty_io_nonblock(tty, file)) {
            retval = -EAGAIN;
            break;
        }
        up_read(&tty->termios_rwsem);

        wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);

        down_read(&tty->termios_rwsem);
    }
 break_out:
    remove_wait_queue(&tty->write_wait, &wait);
    if (nr && tty->fasync)
        set_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
    up_read(&tty->termios_rwsem);
    return (b - buf) ? b - buf : retval;
}

static int n_tty_ioctl(struct tty_struct *tty, unsigned int cmd,
                       unsigned long arg)
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
    clear_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
    //kill_fasync(&tty->fasync, SIGIO, POLL_OUT);
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
