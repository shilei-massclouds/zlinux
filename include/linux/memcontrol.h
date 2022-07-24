/* SPDX-License-Identifier: GPL-2.0-or-later */
/* memcontrol.h - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 */
#ifndef _LINUX_MEMCONTROL_H
#define _LINUX_MEMCONTROL_H

#include <linux/hardirq.h>
/*
#include <linux/cgroup.h>
#include <linux/vm_event_item.h>
#include <linux/jump_label.h>
#include <linux/page_counter.h>
#include <linux/vmpressure.h>
#include <linux/eventfd.h>
*/
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>

/*
 * Bucket for arbitrarily byte-sized objects charged to a memory
 * cgroup. The bucket can be reparented in one piece when the cgroup
 * is destroyed, without having to round up the individual references
 * of all live memory objects in the wild.
 */
struct obj_cgroup {
};

#endif /* _LINUX_MEMCONTROL_H */
