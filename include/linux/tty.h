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
//#include <uapi/linux/tty.h>
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

#endif /* _LINUX_TTY_H */
