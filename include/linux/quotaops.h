/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions for diskquota-operations. When diskquota is configured these
 * macros expand to the right source-code.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 */
#ifndef _LINUX_QUOTAOPS_
#define _LINUX_QUOTAOPS_

#include <linux/fs.h>

#define dquot_file_open     generic_file_open

#endif /* _LINUX_QUOTAOPS_ */
