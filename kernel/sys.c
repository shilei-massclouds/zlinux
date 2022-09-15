// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/kernel/sys.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#if 0
#include <linux/prctl.h>
#include <linux/highuid.h>
#endif
#include <linux/fs.h>
#include <linux/kmod.h>
//#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#if 0
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#endif
#include <linux/security.h>
#if 0
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/syscall_user_dispatch.h>

#include <linux/compat.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/time_namespace.h>
#endif
#include <linux/syscalls.h>
#include <linux/binfmts.h>

#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/loadavg.h>
//#include <linux/sched/stat.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
//#include <linux/sched/cputime.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

//#include <linux/nospec.h>

#if 0
#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>
#endif

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

//#include "uid16.h"

DECLARE_RWSEM(uts_sem);

#define override_architecture(name) 0

/*
 * Work around broken programs that cannot handle "Linux 3.0".
 * Instead we map 3.x to 2.6.40+x, so e.g. 3.0 would be 2.6.40
 * And we map 4.x and later versions to 2.6.60+x, so 4.0/5.0/6.0/... would be
 * 2.6.60.
 */
static int override_release(char __user *release, size_t len)
{
    int ret = 0;

    if (current->personality & UNAME26) {
        panic("%s: UNAME26!\n", __func__);
    }
    return ret;
}

SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
{
    struct new_utsname tmp;

    down_read(&uts_sem);
    memcpy(&tmp, utsname(), sizeof(tmp));

    up_read(&uts_sem);
    if (copy_to_user(name, &tmp, sizeof(tmp)))
        return -EFAULT;

    if (override_release(name->release, sizeof(name->release)))
        return -EFAULT;
    if (override_architecture(name))
        return -EFAULT;
    return 0;
}
