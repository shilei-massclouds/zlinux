/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * UUID/GUID definition
 *
 * Copyright (C) 2010, 2016 Intel Corp.
 *  Huang Ying <ying.huang@intel.com>
 */
#ifndef _LINUX_UUID_H_
#define _LINUX_UUID_H_

#if 0
#include <uapi/linux/uuid.h>
#endif
#include <linux/string.h>

#define UUID_SIZE 16

typedef struct {
    __u8 b[UUID_SIZE];
} uuid_t;

/*
 * The length of a UUID string ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
 * not including trailing NUL.
 */
#define UUID_STRING_LEN     36

#endif /* _LINUX_UUID_H_ */
