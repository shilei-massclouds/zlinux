/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* DO NOT USE in new code! This is solely for MEI due to legacy reasons */
/*
 * UUID/GUID definition
 *
 * Copyright (C) 2010, Intel Corp.
 *  Huang Ying <ying.huang@intel.com>
 */

#ifndef _UAPI_LINUX_UUID_H_
#define _UAPI_LINUX_UUID_H_

#include <linux/types.h>

typedef struct {
    __u8 b[16];
} guid_t;

#endif /* _UAPI_LINUX_UUID_H_ */
