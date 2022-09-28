/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_H
#define _LINUX_TTY_H

#include <linux/fs.h>
#include <linux/major.h>
//#include <linux/termios.h>
#include <linux/workqueue.h>
#include <linux/tty_buffer.h>
#include <linux/tty_driver.h>
#include <linux/tty_ldisc.h>
#include <linux/tty_port.h>
#include <linux/mutex.h>
#include <linux/tty_flags.h>
#include <uapi/linux/tty.h>
#include <linux/rwsem.h>
#include <linux/llist.h>

struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;

    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;

    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    struct ktermios termios, termios_locked;
    char name[64];
    unsigned long flags;
    int count;
    struct winsize winsize;

    struct {
        spinlock_t lock;
        bool stopped;
        bool tco_stopped;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) flow;

    struct {
        spinlock_t lock;
        struct pid *pgrp;
        struct pid *session;
        unsigned char pktstatus;
        bool packet;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) ctrl;

    int hw_stopped;
    unsigned int receive_room;
    int flow_change;

    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;
    struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

    int closing;
    unsigned char *write_buf;
    int write_cnt;
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;

extern struct ktermios tty_std_termios;

void tty_vhangup(struct tty_struct *tty);
void tty_kref_put(struct tty_struct *tty);

/**
 *  tty_kref_get        -   get a tty reference
 *  @tty: tty device
 *
 *  Return a new reference to a tty object. The caller must hold
 *  sufficient locks/counts to ensure that their existing reference cannot
 *  go away
 */

static inline struct tty_struct *tty_kref_get(struct tty_struct *tty)
{
    if (tty)
        kref_get(&tty->kref);
    return tty;
}

void tty_termios_encode_baud_rate(struct ktermios *termios,
                                  speed_t ibaud, speed_t obaud);

void tty_encode_baud_rate(struct tty_struct *tty, speed_t ibaud,
                          speed_t obaud);

unsigned char tty_get_char_size(unsigned int cflag);

speed_t tty_termios_baud_rate(struct ktermios *termios);

void __init n_tty_init(void);

int __init tty_init(void);

unsigned char tty_get_frame_size(unsigned int cflag);

/* Each of a tty's open files has private_data pointing to tty_file_private */
struct tty_file_private {
    struct tty_struct *tty;
    struct file *file;
    struct list_head list;
};

struct pid *tty_get_pgrp(struct tty_struct *tty);
void tty_vhangup_self(void);
void disassociate_ctty(int priv);
dev_t tty_devnum(struct tty_struct *tty);
void proc_clear_tty(struct task_struct *p);
struct tty_struct *get_current_tty(void);
/* tty_io.c */
const char *tty_name(const struct tty_struct *tty);
struct tty_struct *tty_kopen_exclusive(dev_t device);
struct tty_struct *tty_kopen_shared(dev_t device);
void tty_kclose(struct tty_struct *tty);
int tty_dev_name_to_number(const char *name, dev_t *number);

/* tty_mutex.c */
/* functions for preparation of BKL removal */
void tty_lock(struct tty_struct *tty);
int  tty_lock_interruptible(struct tty_struct *tty);
void tty_unlock(struct tty_struct *tty);
void tty_lock_slave(struct tty_struct *tty);
void tty_unlock_slave(struct tty_struct *tty);
void tty_set_lock_subclass(struct tty_struct *tty);

/* tty magic number */
#define TTY_MAGIC       0x5401

int tty_standard_install(struct tty_driver *driver,
                         struct tty_struct *tty);

/**
 * DOC: TTY Struct Flags
 *
 * These bits are used in the :c:member:`tty_struct.flags` field.
 *
 * So that interrupts won't be able to mess up the queues,
 * copy_to_cooked must be atomic with respect to itself, as must
 * tty->write.  Thus, you must use the inline functions set_bit() and
 * clear_bit() to make things atomic.
 *
 * TTY_THROTTLED
 *  Driver input is throttled. The ldisc should call
 *  :c:member:`tty_driver.unthrottle()` in order to resume reception when
 *  it is ready to process more data (at threshold min).
 *
 * TTY_IO_ERROR
 *  If set, causes all subsequent userspace read/write calls on the tty to
 *  fail, returning -%EIO. (May be no ldisc too.)
 *
 * TTY_OTHER_CLOSED
 *  Device is a pty and the other side has closed.
 *
 * TTY_EXCLUSIVE
 *  Exclusive open mode (a single opener).
 *
 * TTY_DO_WRITE_WAKEUP
 *  If set, causes the driver to call the
 *  :c:member:`tty_ldisc_ops.write_wakeup()` method in order to resume
 *  transmission when it can accept more data to transmit.
 *
 * TTY_LDISC_OPEN
 *  Indicates that a line discipline is open. For debugging purposes only.
 *
 * TTY_PTY_LOCK
 *  A flag private to pty code to implement %TIOCSPTLCK/%TIOCGPTLCK logic.
 *
 * TTY_NO_WRITE_SPLIT
 *  Prevent driver from splitting up writes into smaller chunks (preserve
 *  write boundaries to driver).
 *
 * TTY_HUPPED
 *  The TTY was hung up. This is set post :c:member:`tty_driver.hangup()`.
 *
 * TTY_HUPPING
 *  The TTY is in the process of hanging up to abort potential readers.
 *
 * TTY_LDISC_CHANGING
 *  Line discipline for this TTY is being changed. I/O should not block
 *  when this is set. Use tty_io_nonblock() to check.
 *
 * TTY_LDISC_HALTED
 *  Line discipline for this TTY was stopped. No work should be queued to
 *  this ldisc.
 */
#define TTY_THROTTLED       0
#define TTY_IO_ERROR        1
#define TTY_OTHER_CLOSED    2
#define TTY_EXCLUSIVE       3
#define TTY_DO_WRITE_WAKEUP 5
#define TTY_LDISC_OPEN      11
#define TTY_PTY_LOCK        16
#define TTY_NO_WRITE_SPLIT  17
#define TTY_HUPPED          18
#define TTY_HUPPING         19
#define TTY_LDISC_CHANGING  20
#define TTY_LDISC_HALTED    22

void tty_unthrottle(struct tty_struct *tty);

#endif /* _LINUX_TTY_H */
