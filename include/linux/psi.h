/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PSI_H
#define _LINUX_PSI_H

#include <linux/jump_label.h>
//#include <linux/psi_types.h>
#include <linux/sched.h>
//#include <linux/poll.h>
//#include <linux/cgroup-defs.h>

struct seq_file;
struct css_set;

static inline void psi_init(void) {}

static inline void psi_memstall_enter(unsigned long *flags) {}
static inline void psi_memstall_leave(unsigned long *flags) {}

#endif /* _LINUX_PSI_H */
