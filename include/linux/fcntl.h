/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FCNTL_H
#define _LINUX_FCNTL_H

#include <linux/stat.h>
#include <uapi/linux/fcntl.h>

/* List of all valid flags for the open/openat flags argument: */
#define VALID_OPEN_FLAGS \
    (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
     O_APPEND | O_NDELAY | O_NONBLOCK | __O_SYNC | O_DSYNC | \
     FASYNC | O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
     O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)

/* List of all valid flags for the how->resolve argument: */
#define VALID_RESOLVE_FLAGS \
    (RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
     RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

#ifndef force_o_largefile
#define force_o_largefile() (1)
#endif

#endif /* _LINUX_FCNTL_H */
