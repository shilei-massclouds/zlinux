/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  linux/fs/pnode.h
 *
 * (C) Copyright IBM Corporation 2005.
 */
#ifndef _LINUX_PNODE_H
#define _LINUX_PNODE_H

#include <linux/list.h>
#include "mount.h"

#define IS_MNT_SHARED(m) ((m)->mnt.mnt_flags & MNT_SHARED)
#define IS_MNT_UNBINDABLE(m) ((m)->mnt.mnt_flags & MNT_UNBINDABLE)

void mnt_release_group_id(struct mount *);

#endif /* _LINUX_PNODE_H */
