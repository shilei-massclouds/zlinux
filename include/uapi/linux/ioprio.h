/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_IOPRIO_H
#define _UAPI_LINUX_IOPRIO_H

/*
 * Gives us 8 prio classes with 13-bits of data for each class
 */
#define IOPRIO_CLASS_SHIFT  13
#define IOPRIO_CLASS_MASK   0x07
#define IOPRIO_PRIO_MASK    ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(ioprio) \
    (((ioprio) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK)

#endif /* _UAPI_LINUX_IOPRIO_H */
