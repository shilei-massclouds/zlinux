// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/proc/base.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc base directory handling functions
 *
 *  1999, Al Viro. Rewritten. Now it covers the whole per-process part.
 *  Instead of using magical inumbers to determine the kind of object
 *  we allocate and fill in-core inodes upon lookup. They don't even
 *  go into icache. We cache the reference to task_struct upon lookup too.
 *  Eventually it should become a filesystem in its own. We don't use the
 *  rest of procfs anymore.
 *
 *
 *  Simo Piiroinen <simo.piiroinen@nokia.com>:
 *  Smaps information related to shared, private, clean and dirty pages.
 *
 *  Paul Mundt <paul.mundt@nokia.com>:
 *  Overall revision about smaps.
 */

#include <linux/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
//#include <linux/task_io_accounting_ops.h>
#include <linux/init.h>
//#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fdtable.h>
//#include <linux/generic-radix-tree.h>
#include <linux/string.h>
//#include <linux/seq_file.h>
#include <linux/namei.h>
//#include <linux/mnt_namespace.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/kallsyms.h>
//#include <linux/stacktrace.h>
#include <linux/resource.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/printk.h>
#include <linux/cache.h>
#if 0
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/audit.h>
#include <linux/poll.h>
#endif
#include <linux/nsproxy.h>
#include <linux/oom.h>
#include <linux/elf.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/debug.h>
//#include <linux/sched/stat.h>
#include <linux/posix-timers.h>
#if 0
#include <linux/time_namespace.h>
#include <linux/resctrl.h>
#include <linux/cn_proc.h>
#include <trace/events/oom.h>
#endif
#include "internal.h"
//#include "fd.h"

//#include "../../lib/kstrtox.h"

/* NOTE:
 *  Implementing inode permission operations in /proc is almost
 *  certainly an error.  Permission checks need to happen during
 *  each system call not at open time.  The reason is that most of
 *  what we wish to check for permissions in /proc varies at runtime.
 *
 *  The classic example of a problem is opening file descriptors
 *  in /proc for a task before it execs a suid executable.
 */

static u8 nlink_tid __ro_after_init;
static u8 nlink_tgid __ro_after_init;

struct pid_entry {
    const char *name;
    unsigned int len;
    umode_t mode;
    const struct inode_operations *iop;
    const struct file_operations *fop;
    union proc_op op;
};

#define NOD(NAME, MODE, IOP, FOP, OP) {         \
    .name = (NAME),                 \
    .len  = sizeof(NAME) - 1,       \
    .mode = MODE,                   \
    .iop  = IOP,                    \
    .fop  = FOP,                    \
    .op   = OP,                     \
}

#define LNK(NAME, get_link) \
    NOD(NAME, (S_IFLNK|S_IRWXUGO),                  \
        &proc_pid_link_inode_operations, NULL,      \
        { .proc_get_link = get_link } )

static int proc_exe_link(struct dentry *dentry, struct path *exe_path)
{
#if 0
    struct task_struct *task;
    struct file *exe_file;

    task = get_proc_task(d_inode(dentry));
    if (!task)
        return -ENOENT;
    exe_file = get_task_exe_file(task);
    put_task_struct(task);
    if (exe_file) {
        *exe_path = exe_file->f_path;
        path_get(&exe_file->f_path);
        fput(exe_file);
        return 0;
    } else
        return -ENOENT;
#endif
    panic("%s: END!\n", __func__);
}

/*
 * Tasks
 */
static const struct pid_entry tid_base_stuff[] = {
#if 0
    DIR("fd",        S_IRUSR|S_IXUSR, proc_fd_inode_operations, proc_fd_operations),
    DIR("fdinfo",    S_IRUGO|S_IXUGO, proc_fdinfo_inode_operations, proc_fdinfo_operations),
    DIR("ns",    S_IRUSR|S_IXUGO, proc_ns_dir_inode_operations, proc_ns_dir_operations),
    DIR("net",        S_IRUGO|S_IXUGO, proc_net_inode_operations, proc_net_operations),
    REG("environ",   S_IRUSR, proc_environ_operations),
    REG("auxv",      S_IRUSR, proc_auxv_operations),
    ONE("status",    S_IRUGO, proc_pid_status),
    ONE("personality", S_IRUSR, proc_pid_personality),
    ONE("limits",    S_IRUGO, proc_pid_limits),
    NOD("comm",      S_IFREG|S_IRUGO|S_IWUSR,
             &proc_tid_comm_inode_operations,
             &proc_pid_set_comm_operations, {}),
    ONE("syscall",   S_IRUSR, proc_pid_syscall),
#endif
    LNK("exe",       proc_exe_link),
};

static const struct pid_entry tgid_base_stuff[] = {
};

static int proc_pid_readlink(struct dentry * dentry,
                             char __user * buffer, int buflen)
{
    panic("%s: END!\n", __func__);
}

static const char *proc_pid_get_link(struct dentry *dentry,
                                     struct inode *inode,
                                     struct delayed_call *done)
{
    panic("%s: END!\n", __func__);
}

int proc_setattr(struct user_namespace *mnt_userns, struct dentry *dentry,
                 struct iattr *attr)
{
    panic("%s: END!\n", __func__);
}

const struct inode_operations proc_pid_link_inode_operations = {
    .readlink   = proc_pid_readlink,
    .get_link   = proc_pid_get_link,
    .setattr    = proc_setattr,
};

/*
 * Count the number of hardlinks for the pid_entry table, excluding the .
 * and .. links.
 */
static unsigned int __init pid_entry_nlink(const struct pid_entry *entries,
                                           unsigned int n)
{
    unsigned int i;
    unsigned int count;

    count = 2;
    for (i = 0; i < n; ++i) {
        if (S_ISDIR(entries[i].mode))
            ++count;
    }

    return count;
}

void __init set_proc_pid_nlink(void)
{
    nlink_tid = pid_entry_nlink(tid_base_stuff, ARRAY_SIZE(tid_base_stuff));
    nlink_tgid = pid_entry_nlink(tgid_base_stuff, ARRAY_SIZE(tgid_base_stuff));
}
