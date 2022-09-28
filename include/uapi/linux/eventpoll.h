
/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  include/linux/eventpoll.h ( Efficient event polling implementation )
 *  Copyright (C) 2001,...,2006  Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _UAPI_LINUX_EVENTPOLL_H
#define _UAPI_LINUX_EVENTPOLL_H

/* For O_CLOEXEC */
#include <linux/fcntl.h>
#include <linux/types.h>

/* Flags for epoll_create1.  */
#define EPOLL_CLOEXEC O_CLOEXEC

/* Valid opcodes to issue to sys_epoll_ctl() */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* Epoll event masks */
#define EPOLLIN     (__force __poll_t)0x00000001
#define EPOLLPRI    (__force __poll_t)0x00000002
#define EPOLLOUT    (__force __poll_t)0x00000004
#define EPOLLERR    (__force __poll_t)0x00000008
#define EPOLLHUP    (__force __poll_t)0x00000010
#define EPOLLNVAL   (__force __poll_t)0x00000020
#define EPOLLRDNORM (__force __poll_t)0x00000040
#define EPOLLRDBAND (__force __poll_t)0x00000080
#define EPOLLWRNORM (__force __poll_t)0x00000100
#define EPOLLWRBAND (__force __poll_t)0x00000200
#define EPOLLMSG    (__force __poll_t)0x00000400
#define EPOLLRDHUP  (__force __poll_t)0x00002000

#endif /* _UAPI_LINUX_EVENTPOLL_H */
