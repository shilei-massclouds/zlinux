/*
 * kmod - the kernel module loader
 */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#if 0
#include <linux/binfmts.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#endif
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/cred.h>
#if 0
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#endif
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#if 0
#include <linux/resource.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#endif
#include <linux/rwsem.h>
#if 0
#include <linux/ptrace.h>
#include <linux/async.h>
#endif
#include <linux/uaccess.h>

/**
 * __request_module - try to load a kernel module
 * @wait: wait (or not) for the operation to complete
 * @fmt: printf style format string for the name of the module
 * @...: arguments as specified in the format string
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code or positive exit code from
 * "modprobe" on failure. Note that a successful module load does not mean
 * the module did not then unload and exit on an error of its own. Callers
 * must check that the service they requested is now available not blindly
 * invoke it.
 *
 * If module auto-loading support is disabled then this function
 * simply returns -ENOENT.
 */
int __request_module(bool wait, const char *fmt, ...)
{
    panic("%s: END!\n", __func__);
}
