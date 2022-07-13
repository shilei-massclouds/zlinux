/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/writeback.h
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

#include <linux/sched.h>
#include <linux/fs.h>
/*
#include <linux/workqueue.h>
#include <linux/flex_proportions.h>
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>
*/

/*
 * mm/page-writeback.c
 */
bool node_dirty_ok(struct pglist_data *pgdat);

#endif  /* WRITEBACK_H */
