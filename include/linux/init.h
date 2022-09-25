/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <linux/compiler.h>
#include <linux/types.h>

#define __noinitretpoline

/* These are for everybody (although not all archs will actually
   discard it in modules) */
#define __init \
    __section(".init.text") __cold  __latent_entropy __noinitretpoline __nocfi

#ifdef MODULE
#define __exitused
#else
#define __exitused __used
#endif

#define __exit __section(".exit.text") __exitused __cold notrace

#define __initdata  __section(".init.data")
#define __initconst __section(".init.rodata")
#define __exitdata  __section(".exit.data")
#define __exit_call __used __section(".exitcall.exit")

/* Used for MEMORY_HOTPLUG */
#define __meminit __section(".meminit.text") __cold notrace __latent_entropy

#define __meminitdata    __section(".meminit.data")
#define __meminitconst   __section(".meminit.rodata")
#define __memexit        __section(".memexit.text") __exitused __cold notrace
#define __memexitdata    __section(".memexit.data")
#define __memexitconst   __section(".memexit.rodata")

#define __ref       __section(".ref.text") noinline
#define __refdata   __section(".ref.data")
#define __refconst  __section(".ref.rodata")

/* For assembly routines */
#define __HEAD  .section ".head.text","ax"
#define __INIT  .section ".init.text","ax"

/* Format: <modname>__<counter>_<line>_<fn> */
#define __initcall_id(fn)           \
    __PASTE(__KBUILD_MODNAME,       \
    __PASTE(__,                     \
    __PASTE(__COUNTER__,            \
    __PASTE(_,                      \
    __PASTE(__LINE__,               \
    __PASTE(_, fn))))))

#define __initcall_name(prefix, __iid, id)  \
    __PASTE(__,                             \
    __PASTE(prefix,                         \
    __PASTE(__,                             \
    __PASTE(__iid, id))))

#define __initcall_section(__sec, __iid) \
    #__sec ".init"

#define __initcall_stub(fn, __iid, id)  fn

#define ____define_initcall(fn, __unused, __name, __sec) \
    static initcall_t __name __used \
        __attribute__((__section__(__sec))) = fn;

#define __unique_initcall(fn, id, __sec, __iid) \
    ____define_initcall(fn,                     \
        __initcall_stub(fn, __iid, id),         \
        __initcall_name(initcall, __iid, id),   \
        __initcall_section(__sec, __iid))

#define ___define_initcall(fn, id, __sec) \
    __unique_initcall(fn, id, __sec, __initcall_id(fn))

#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)

/*
 * Early initcalls run before initializing SMP.
 *
 * Only for built-in code, not modules.
 */
#define early_initcall(fn)          __define_initcall(fn, early)

/*
 * A "pure" initcall has no dependencies on anything else, and purely
 * initializes variables that couldn't be statically initialized.
 *
 * This only exists for built-in code, not for modules.
 * Keep main.c:initcall_level_names[] in sync.
 */
#define pure_initcall(fn)           __define_initcall(fn, 0)

#define core_initcall(fn)           __define_initcall(fn, 1)
#define core_initcall_sync(fn)      __define_initcall(fn, 1s)
#define postcore_initcall(fn)       __define_initcall(fn, 2)
#define postcore_initcall_sync(fn)  __define_initcall(fn, 2s)
#define arch_initcall(fn)           __define_initcall(fn, 3)
#define arch_initcall_sync(fn)      __define_initcall(fn, 3s)
#define subsys_initcall(fn)         __define_initcall(fn, 4)
#define subsys_initcall_sync(fn)    __define_initcall(fn, 4s)
#define fs_initcall(fn)             __define_initcall(fn, 5)
#define fs_initcall_sync(fn)        __define_initcall(fn, 5s)
#define rootfs_initcall(fn)         __define_initcall(fn, rootfs)
#define device_initcall(fn)         __define_initcall(fn, 6)
#define device_initcall_sync(fn)    __define_initcall(fn, 6s)
#define late_initcall(fn)           __define_initcall(fn, 7)
#define late_initcall_sync(fn)      __define_initcall(fn, 7s)

#define __initcall(fn) device_initcall(fn)

#define __exitcall(fn) \
    static exitcall_t __exitcall_##fn __exit_call = fn

#ifndef __ASSEMBLY__

struct obs_kernel_param {
    const char *str;
    int (*setup_func)(char *);
    int early;
};

extern char __initdata boot_command_line[];

/* used by init/main.c */
void setup_arch(char **);

/*
 * Only for really core code.  See moduleparam.h for the normal way.
 *
 * Force the alignment so the compiler doesn't space elements of the
 * obs_kernel_param "array" too far apart in .init.setup.
 */
#define __setup_param(str, unique_id, fn, early)                \
    static const char __setup_str_##unique_id[] __initconst     \
        __aligned(1) = str;                                     \
    static struct obs_kernel_param __setup_##unique_id          \
        __used __section(".init.setup")                         \
        __aligned(__alignof__(struct obs_kernel_param))         \
        = { __setup_str_##unique_id, fn, early }

#define __setup(str, fn) __setup_param(str, fn, fn, 0)

/*
 * NOTE: fn is as per module_param, not __setup!
 * Emits warning if fn returns non-zero.
 */
#define early_param(str, fn) __setup_param(str, fn, fn, 1)

#define console_initcall(fn) \
    ___define_initcall(fn, con, .con_initcall)

/* Relies on boot_command_line being set */
void __init parse_early_param(void);
void __init parse_early_options(char *cmdline);

/*
 * Used for initialization calls..
 */
typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

typedef initcall_t initcall_entry_t;

static inline initcall_t initcall_from_entry(initcall_entry_t *entry)
{
    return *entry;
}

void __init init_rootfs(void);

extern struct file_system_type rootfs_fs_type;

void prepare_namespace(void);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_INIT_H */
