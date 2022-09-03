/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sysctl.h: General linux system control interface
 *
 * Begun 24 March 1995, Stephen Tweedie
 *
 ****************************************************************
 ****************************************************************
 **
 **  WARNING:
 **  The values in this file are exported to user space via
 **  the sysctl() binary interface.  Do *NOT* change the
 **  numbering of any existing values here, and do not change
 **  any numbers within any one set of values.  If you have to
 **  redefine an existing interface, use a new number for it.
 **  The kernel will then return -ENOTDIR to any application using
 **  the old binary interface.
 **
 ****************************************************************
 ****************************************************************
 */
#ifndef _LINUX_SYSCTL_H
#define _LINUX_SYSCTL_H

#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/uidgid.h>
//#include <uapi/linux/sysctl.h>

/* For the /proc/sys support */
struct completion;
struct ctl_table;
struct nsproxy;
struct ctl_table_root;
struct ctl_table_header;
struct ctl_dir;

#endif /* _LINUX_SYSCTL_H */
