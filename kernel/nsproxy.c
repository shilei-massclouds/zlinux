// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2006 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 *
 *  Jun 2006 - namespaces support
 *             OpenVZ, SWsoft Inc.
 *             Pavel Emelianov <xemul@openvz.org>
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/pid_namespace.h>
#if 0
#include <linux/mnt_namespace.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/cgroup.h>
#include <linux/perf_event.h>
#endif

struct nsproxy init_nsproxy = {
#if 0
    .count          = ATOMIC_INIT(1),
    .uts_ns         = &init_uts_ns,
    .ipc_ns         = &init_ipc_ns,
    .mnt_ns         = NULL,
    .net_ns         = &init_net,
    .cgroup_ns      = &init_cgroup_ns,
    .time_ns        = &init_time_ns,
    .time_ns_for_children   = &init_time_ns,
#endif
    .pid_ns_for_children    = &init_pid_ns,
};
