/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * NUMA memory policies for Linux.
 * Copyright 2003,2004 Andi Kleen SuSE Labs
 */
#ifndef _UAPI_LINUX_MEMPOLICY_H
#define _UAPI_LINUX_MEMPOLICY_H

#include <linux/errno.h>

/*
 * These bit locations are exposed in the vm.zone_reclaim_mode sysctl
 * ABI.  New bits are OK, but existing bits can never change.
 */
#define RECLAIM_ZONE    (1<<0)  /* Run shrink_inactive_list on the zone */
#define RECLAIM_WRITE   (1<<1)  /* Writeout pages during reclaim */
#define RECLAIM_UNMAP   (1<<2)  /* Unmap pages during reclaim */

#endif /* _UAPI_LINUX_MEMPOLICY_H */
