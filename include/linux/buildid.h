/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BUILDID_H
#define _LINUX_BUILDID_H

#include <linux/mm_types.h>

#define BUILD_ID_SIZE_MAX 20

#if 0
int build_id_parse(struct vm_area_struct *vma,
                   unsigned char *build_id, __u32 *size);
int build_id_parse_buf(const void *buf, unsigned char *build_id, u32 buf_size);
#endif

static inline void init_vmlinux_build_id(void) { }

#endif
