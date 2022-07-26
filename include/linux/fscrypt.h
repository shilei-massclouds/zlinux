/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fscrypt.h: declarations for per-file encryption
 *
 * Filesystems that implement per-file encryption must include this header
 * file.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */
#ifndef _LINUX_FSCRYPT_H
#define _LINUX_FSCRYPT_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
//#include <uapi/linux/fscrypt.h>

/**
 * fscrypt_inode_uses_fs_layer_crypto() - test whether an inode uses fs-layer
 *                    encryption
 * @inode: an inode. If encrypted, its key must be set up.
 *
 * Return: true if the inode requires file contents encryption and if the
 *     encryption should be done in the filesystem layer rather than in the
 *     block layer via blk-crypto.
 */
static inline bool fscrypt_inode_uses_fs_layer_crypto(const struct inode *inode)
{
    return false;
}

#endif  /* _LINUX_FSCRYPT_H */
