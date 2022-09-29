/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_FLIP_H
#define _LINUX_TTY_FLIP_H

#include <linux/tty_buffer.h>
#include <linux/tty_port.h>

struct tty_ldisc;

int tty_buffer_set_limit(struct tty_port *port, int limit);
unsigned int tty_buffer_space_avail(struct tty_port *port);
int tty_buffer_request_room(struct tty_port *port, size_t size);
int tty_insert_flip_string_flags(struct tty_port *port,
        const unsigned char *chars, const char *flags, size_t size);
int tty_insert_flip_string_fixed_flag(struct tty_port *port,
        const unsigned char *chars, char flag, size_t size);
int tty_prepare_flip_string(struct tty_port *port, unsigned char **chars,
        size_t size);
void tty_flip_buffer_push(struct tty_port *port);
int __tty_insert_flip_char(struct tty_port *port, unsigned char ch, char flag);

#endif /* _LINUX_TTY_FLIP_H */
