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

#endif /* _TTY_INTERNAL_H */
