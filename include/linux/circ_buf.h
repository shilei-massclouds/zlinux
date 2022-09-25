/* SPDX-License-Identifier: GPL-2.0 */
/*
 * See Documentation/core-api/circular-buffers.rst for more information.
 */

#ifndef _LINUX_CIRC_BUF_H
#define _LINUX_CIRC_BUF_H 1

struct circ_buf {
    char *buf;
    int head;
    int tail;
};

#endif /* _LINUX_CIRC_BUF_H  */
