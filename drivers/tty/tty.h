/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TTY core internal functions
 */

#ifndef _TTY_INTERNAL_H
#define _TTY_INTERNAL_H

void tty_buffer_free_all(struct tty_port *port);
void tty_buffer_flush(struct tty_struct *tty, struct tty_ldisc *ld);
void tty_buffer_init(struct tty_port *port);
void tty_buffer_set_lock_subclass(struct tty_port *port);
bool tty_buffer_restart_work(struct tty_port *port);
bool tty_buffer_cancel_work(struct tty_port *port);
void tty_buffer_flush_work(struct tty_port *port);

int tty_ldisc_setup(struct tty_struct *tty, struct tty_struct *o_tty);
void tty_ldisc_release(struct tty_struct *tty);
int __must_check tty_ldisc_init(struct tty_struct *tty);
void tty_ldisc_deinit(struct tty_struct *tty);

int tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout);
void tty_ldisc_unlock(struct tty_struct *tty);

const char *tty_driver_name(const struct tty_struct *tty);

#define tty_msg(fn, tty, f, ...) \
    fn("%s %s: " f, tty_driver_name(tty), tty_name(tty), ##__VA_ARGS__)

#define tty_debug(tty, f, ...)  tty_msg(pr_debug, tty, f, ##__VA_ARGS__)
#define tty_notice(tty, f, ...) tty_msg(pr_notice, tty, f, ##__VA_ARGS__)
#define tty_warn(tty, f, ...)   tty_msg(pr_warn, tty, f, ##__VA_ARGS__)
#define tty_err(tty, f, ...)    tty_msg(pr_err, tty, f, ##__VA_ARGS__)

#define tty_info_ratelimited(tty, f, ...) \
        tty_msg(pr_info_ratelimited, tty, f, ##__VA_ARGS__)

speed_t tty_termios_input_baud_rate(struct ktermios *termios);

#endif /* _TTY_INTERNAL_H */
