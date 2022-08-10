/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERRNO_H
#define _LINUX_ERRNO_H

#include <uapi/linux/errno.h>

#define ERESTARTNOINTR  513
#define EPROBE_DEFER    517 /* Driver requests probe retry */
#define EOPENSTALE      518 /* open found a stale dentry */
#define ENOPARAM        519 /* Parameter not supported */
#define ENOTSUPP        524 /* Operation is not supported */

#endif /* _LINUX_ERRNO_H */
