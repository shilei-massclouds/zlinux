/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX__INIT_TASK_H
#define _LINUX__INIT_TASK_H

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/mm_types.h>

#include <asm/thread_info.h>

#define INIT_TASK_COMM "swapper"

extern struct nsproxy init_nsproxy;

#endif /* _LINUX__INIT_TASK_H */
