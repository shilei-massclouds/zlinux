/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FCNTL_H
#define _UAPI_LINUX_FCNTL_H

#if 0
#include <asm/fcntl.h>
#include <linux/openat2.h>
#endif

/*
 * Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
 * used to clear any hints previously set.
 */
#define RWH_WRITE_LIFE_NOT_SET  0
#define RWH_WRITE_LIFE_NONE     1
#define RWH_WRITE_LIFE_SHORT    2
#define RWH_WRITE_LIFE_MEDIUM   3
#define RWH_WRITE_LIFE_LONG     4
#define RWH_WRITE_LIFE_EXTREME  5

/*
 * Types of seals
 */
#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#define F_SEAL_FUTURE_WRITE 0x0010  /* prevent future writes while mapped */
/* (1U << 31) is reserved for signed error codes */

#endif /* _UAPI_LINUX_FCNTL_H */
