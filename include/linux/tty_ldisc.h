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

struct tty_ldisc_ops {
    char    *name;
    int num;

    /*
     * The following routines are called from above.
     */
    int (*open)(struct tty_struct *tty);
    void    (*close)(struct tty_struct *tty);
    void    (*flush_buffer)(struct tty_struct *tty);
    ssize_t (*read)(struct tty_struct *tty, struct file *file,
            unsigned char *buf, size_t nr,
            void **cookie, unsigned long offset);
    ssize_t (*write)(struct tty_struct *tty, struct file *file,
             const unsigned char *buf, size_t nr);
    int (*ioctl)(struct tty_struct *tty, unsigned int cmd,
            unsigned long arg);
    int (*compat_ioctl)(struct tty_struct *tty, unsigned int cmd,
            unsigned long arg);
    void    (*set_termios)(struct tty_struct *tty, struct ktermios *old);
    __poll_t (*poll)(struct tty_struct *tty, struct file *file,
                 struct poll_table_struct *wait);
    void    (*hangup)(struct tty_struct *tty);

    /*
     * The following routines are called from below.
     */
    void    (*receive_buf)(struct tty_struct *tty, const unsigned char *cp,
                   const char *fp, int count);
    void    (*write_wakeup)(struct tty_struct *tty);
    void    (*dcd_change)(struct tty_struct *tty, unsigned int status);
    int (*receive_buf2)(struct tty_struct *tty, const unsigned char *cp,
                const char *fp, int count);

    struct  module *owner;
};

struct tty_ldisc {
    struct tty_ldisc_ops *ops;
    struct tty_struct *tty;
};

void __init_ldsem(struct ld_semaphore *sem, const char *name,
                  struct lock_class_key *key);

#define init_ldsem(sem)                     \
do {                                \
    static struct lock_class_key __key;         \
                                \
    __init_ldsem((sem), #sem, &__key);          \
} while (0)

extern const struct seq_operations tty_ldiscs_seq_ops;

struct tty_ldisc *tty_ldisc_ref(struct tty_struct *);
void tty_ldisc_deref(struct tty_ldisc *);
struct tty_ldisc *tty_ldisc_ref_wait(struct tty_struct *);

void tty_ldisc_flush(struct tty_struct *tty);

int tty_register_ldisc(struct tty_ldisc_ops *new_ldisc);
void tty_unregister_ldisc(struct tty_ldisc_ops *ldisc);
int tty_set_ldisc(struct tty_struct *tty, int disc);

int ldsem_down_read(struct ld_semaphore *sem, long timeout);
int ldsem_down_read_trylock(struct ld_semaphore *sem);
int ldsem_down_write(struct ld_semaphore *sem, long timeout);
int ldsem_down_write_trylock(struct ld_semaphore *sem);
void ldsem_up_read(struct ld_semaphore *sem);
void ldsem_up_write(struct ld_semaphore *sem);

#endif /* _LINUX_TTY_LDISC_H */
