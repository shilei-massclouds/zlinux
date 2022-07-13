// SPDX-License-Identifier: GPL-2.0-or-later
/* Provide a way to create a superblock configuration context within the kernel
 * that allows a superblock to be set up prior to mounting.
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/fs_context.h>
//#include <linux/fs_parser.h>
#include <linux/fs.h>
#include <linux/mount.h>
//#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/magic.h>
#if 0
#include <linux/security.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#endif
#include <asm/sections.h>
//#include "mount.h"
#include "internal.h"

/**
 * alloc_fs_context - Create a filesystem context.
 * @fs_type: The filesystem type.
 * @reference: The dentry from which this one derives (or NULL)
 * @sb_flags: Filesystem/superblock flags (SB_*)
 * @sb_flags_mask: Applicable members of @sb_flags
 * @purpose: The purpose that this configuration shall be used for.
 *
 * Open a filesystem and create a mount context.  The mount context is
 * initialised with the supplied flags and, if a submount/automount from
 * another superblock (referred to by @reference) is supplied, may have
 * parameters such as namespaces copied across from that superblock.
 */
static struct fs_context *
alloc_fs_context(struct file_system_type *fs_type,
                 struct dentry *reference,
                 unsigned int sb_flags,
                 unsigned int sb_flags_mask,
                 enum fs_context_purpose purpose)
{
    int (*init_fs_context)(struct fs_context *);
    struct fs_context *fc;
    int ret = -ENOMEM;

    fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
    if (!fc)
        return ERR_PTR(-ENOMEM);

    fc->purpose = purpose;
    fc->sb_flags = sb_flags;
    fc->sb_flags_mask = sb_flags_mask;
    fc->fs_type = get_filesystem(fs_type);
#if 0
    fc->cred    = get_current_cred();
    fc->net_ns  = get_net(current->nsproxy->net_ns);
    fc->log.prefix  = fs_type->name;
#endif

    panic("%s: END!\n", __func__);
}

struct fs_context *
fs_context_for_mount(struct file_system_type *fs_type, unsigned int sb_flags)
{
    return alloc_fs_context(fs_type, NULL, sb_flags, 0, FS_CONTEXT_FOR_MOUNT);
}
EXPORT_SYMBOL(fs_context_for_mount);
