/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HIGHUID_H
#define _LINUX_HIGHUID_H

#include <linux/types.h>

/*
 * general notes:
 *
 * CONFIG_UID16 is defined if the given architecture needs to
 * support backwards compatibility for old system calls.
 *
 * kernel code should use uid_t and gid_t at all times when dealing with
 * kernel-private data.
 *
 * old_uid_t and old_gid_t should only be different if CONFIG_UID16 is
 * defined, else the platform should provide dummy typedefs for them
 * such that they are equivalent to __kernel_{u,g}id_t.
 *
 * uid16_t and gid16_t are used on all architectures. (when dealing
 * with structures hard coded to 16 bits, such as in filesystems)
 */

/*
 * This is the "overflow" UID and GID. They are used to signify uid/gid
 * overflow to old programs when they request uid/gid information but are
 * using the old 16 bit interfaces.
 * When you run a libc5 program, it will think that all highuid files or
 * processes are owned by this uid/gid.
 * The idea is that it's better to do so than possibly return 0 in lieu of
 * 65536, etc.
 */

extern int overflowuid;
extern int overflowgid;

extern void __bad_uid(void);
extern void __bad_gid(void);

#define DEFAULT_OVERFLOWUID 65534
#define DEFAULT_OVERFLOWGID 65534

#endif /* _LINUX_HIGHUID_H */
