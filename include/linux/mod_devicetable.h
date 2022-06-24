/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Device tables which are exported to userspace via
 * scripts/mod/file2alias.c.  You must keep that file in sync with this
 * header.
 */

#ifndef LINUX_MOD_DEVICETABLE_H
#define LINUX_MOD_DEVICETABLE_H

#ifdef __KERNEL__
#include <linux/types.h>
//#include <linux/uuid.h>
typedef unsigned long kernel_ulong_t;
#endif

/*
 * Struct used for matching a device
 */
struct of_device_id {
    char    name[32];
    char    type[32];
    char    compatible[128];
    const void *data;
};

#endif /* LINUX_MOD_DEVICETABLE_H */
