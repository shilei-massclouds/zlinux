/*
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *       2000 Transmeta Corp.
 *       2000-2001 Christoph Rohland
 *       2000-2001 SAP AG
 *       2002 Red Hat Inc.
 * Copyright (C) 2002-2011 Hugh Dickins.
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

#include <linux/fs.h>
#include <linux/init.h>
#if 0
#include <linux/vfs.h>
#endif
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/pagemap.h>
#if 0
#include <linux/file.h>
#endif
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/sched/signal.h>
#include <linux/export.h>
#include <linux/swap.h>
#if 0
#include <linux/uio.h>
#include <linux/khugepaged.h>
#include <linux/hugetlb.h>
#include <linux/swapfile.h>
#endif
#include <linux/fs_parser.h>

/*
 * This virtual memory filesystem is heavily based on the ramfs. It
 * extends ramfs by the ability to use swap and honor resource limits
 * which makes it a completely usable filesystem.
 */

#include <linux/exportfs.h>
#if 0
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/mman.h>
#endif
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/writeback.h>
#if 0
#include <linux/pagevec.h>
#include <linux/percpu_counter.h>
#include <linux/falloc.h>
#include <linux/splice.h>
#include <linux/security.h>
#include <linux/swapops.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#endif
#include <linux/ctype.h>
//#include <linux/migrate.h>
#include <linux/highmem.h>
//#include <linux/seq_file.h>
#include <linux/magic.h>
#if 0
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <uapi/linux/memfd.h>
#include <linux/userfaultfd_k.h>
#include <linux/rmap.h>
#endif
#include <linux/uuid.h>
#include <linux/uaccess.h>

#include "internal.h"

/*
 * Definitions for "huge tmpfs": tmpfs mounted with the huge= option
 *
 * SHMEM_HUGE_NEVER:
 *  disables huge pages for the mount;
 * SHMEM_HUGE_ALWAYS:
 *  enables huge pages for the mount;
 * SHMEM_HUGE_WITHIN_SIZE:
 *  only allocate huge pages if the page will be fully within i_size,
 *  also respect fadvise()/madvise() hints;
 * SHMEM_HUGE_ADVISE:
 *  only allocate huge pages if requested with fadvise()/madvise();
 */

#define SHMEM_HUGE_NEVER        0
#define SHMEM_HUGE_ALWAYS       1
#define SHMEM_HUGE_WITHIN_SIZE  2
#define SHMEM_HUGE_ADVISE       3

static struct vfsmount *shm_mnt;

struct shmem_options {
    unsigned long long blocks;
    unsigned long long inodes;
    //struct mempolicy *mpol;
    kuid_t uid;
    kgid_t gid;
    umode_t mode;
    bool full_inums;
    int huge;
    int seen;
#define SHMEM_SEEN_BLOCKS 1
#define SHMEM_SEEN_INODES 2
#define SHMEM_SEEN_HUGE 4
#define SHMEM_SEEN_INUMS 8
};

static vm_fault_t shmem_fault(struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

static const struct vm_operations_struct shmem_vm_ops = {
    .fault      = shmem_fault,
    .map_pages  = filemap_map_pages,
};

static unsigned long shmem_default_max_blocks(void)
{
    return totalram_pages() / 2;
}

static unsigned long shmem_default_max_inodes(void)
{
    unsigned long nr_pages = totalram_pages();

    return min(nr_pages - totalhigh_pages(), nr_pages / 2);
}

static struct dentry *shmem_get_parent(struct dentry *child)
{
    return ERR_PTR(-ESTALE);
}

static int shmem_encode_fh(struct inode *inode, __u32 *fh, int *len,
                           struct inode *parent)
{
    panic("%s: END!\n", __func__);
}

static struct dentry *
shmem_fh_to_dentry(struct super_block *sb,
                   struct fid *fid, int fh_len, int fh_type)
{
    panic("%s: END!\n", __func__);
}

static const struct export_operations shmem_export_ops = {
    .get_parent     = shmem_get_parent,
    .encode_fh      = shmem_encode_fh,
    .fh_to_dentry   = shmem_fh_to_dentry,
};

static inline struct shmem_sb_info *SHMEM_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

static void shmem_put_super(struct super_block *sb)
{
    struct shmem_sb_info *sbinfo = SHMEM_SB(sb);

#if 0
    free_percpu(sbinfo->ino_batch);
    percpu_counter_destroy(&sbinfo->used_blocks);
#endif
    kfree(sbinfo);
    sb->s_fs_info = NULL;
    panic("%s: END!\n", __func__);
}

static int shmem_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct shmem_options *ctx = fc->fs_private;
    struct inode *inode;
    struct shmem_sb_info *sbinfo;

    /* Round up to L1_CACHE_BYTES to resist false sharing */
    sbinfo = kzalloc(max((int)sizeof(struct shmem_sb_info),
                         L1_CACHE_BYTES), GFP_KERNEL);
    if (!sbinfo)
        return -ENOMEM;

    sb->s_fs_info = sbinfo;

    /*
     * Per default we only allow half of the physical ram per
     * tmpfs instance, limiting inodes to one per page of lowmem;
     * but the internal instance is left unlimited.
     */
    if (!(sb->s_flags & SB_KERNMOUNT)) {
        if (!(ctx->seen & SHMEM_SEEN_BLOCKS))
            ctx->blocks = shmem_default_max_blocks();
        if (!(ctx->seen & SHMEM_SEEN_INODES))
            ctx->inodes = shmem_default_max_inodes();
        if (!(ctx->seen & SHMEM_SEEN_INUMS))
            ctx->full_inums = false;
    } else {
        sb->s_flags |= SB_NOUSER;
    }
    sb->s_export_op = &shmem_export_ops;
    sb->s_flags |= SB_NOSEC;

    sbinfo->max_blocks = ctx->blocks;
    sbinfo->free_inodes = sbinfo->max_inodes = ctx->inodes;
    if (sb->s_flags & SB_KERNMOUNT) {
#if 0
        sbinfo->ino_batch = alloc_percpu(ino_t);
        if (!sbinfo->ino_batch)
            goto failed;
#endif
        panic("%s: SB_KERNMOUNT!\n", __func__);
    }
    sbinfo->uid = ctx->uid;
    sbinfo->gid = ctx->gid;
    sbinfo->full_inums = ctx->full_inums;
    sbinfo->mode = ctx->mode;
    sbinfo->huge = ctx->huge;

    raw_spin_lock_init(&sbinfo->stat_lock);
    if (percpu_counter_init(&sbinfo->used_blocks, 0, GFP_KERNEL))
        goto failed;
    spin_lock_init(&sbinfo->shrinklist_lock);
    INIT_LIST_HEAD(&sbinfo->shrinklist);

    panic("%s: END!\n", __func__);
    return 0;

 failed:
    shmem_put_super(sb);
    return -ENOMEM;
}

static void shmem_free_fc(struct fs_context *fc)
{
    struct shmem_options *ctx = fc->fs_private;

    if (ctx)
        kfree(ctx);
}

static int shmem_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, shmem_fill_super);
}

static int shmem_parse_options(struct fs_context *fc, void *data)
{
    char *options = data;

    while (options != NULL) {
        panic("%s: has options!\n", __func__);
    }
    return 0;
}

enum shmem_param {
    Opt_gid,
    Opt_huge,
    Opt_mode,
    Opt_mpol,
    Opt_nr_blocks,
    Opt_nr_inodes,
    Opt_size,
    Opt_uid,
    Opt_inode32,
    Opt_inode64,
};

static const struct constant_table shmem_param_enums_huge[] = {
    {"never",   SHMEM_HUGE_NEVER },
    {"always",  SHMEM_HUGE_ALWAYS },
    {"within_size", SHMEM_HUGE_WITHIN_SIZE },
    {"advise",  SHMEM_HUGE_ADVISE },
    {}
};

const struct fs_parameter_spec shmem_fs_parameters[] = {
    fsparam_u32   ("gid",       Opt_gid),
    fsparam_enum  ("huge",      Opt_huge,  shmem_param_enums_huge),
    fsparam_u32oct("mode",      Opt_mode),
    fsparam_string("mpol",      Opt_mpol),
    fsparam_string("nr_blocks", Opt_nr_blocks),
    fsparam_string("nr_inodes", Opt_nr_inodes),
    fsparam_string("size",      Opt_size),
    fsparam_u32   ("uid",       Opt_uid),
    fsparam_flag  ("inode32",   Opt_inode32),
    fsparam_flag  ("inode64",   Opt_inode64),
    {}
};

static int shmem_parse_one(struct fs_context *fc, struct fs_parameter *param)
{
    struct shmem_options *ctx = fc->fs_private;
    struct fs_parse_result result;
    unsigned long long size;
    char *rest;
    int opt;

    opt = fs_parse(fc, shmem_fs_parameters, param, &result);
    if (opt < 0)
        return opt;

    panic("%s: END!\n", __func__);
}

/*
 * Reconfigure a shmem filesystem.
 *
 * Note that we disallow change from limited->unlimited blocks/inodes while any
 * are in use; but we must separately disallow unlimited->limited, because in
 * that case we have no record of how much is already in use.
 */
static int shmem_reconfigure(struct fs_context *fc)
{
    panic("%s: END!\n", __func__);
}

static const struct fs_context_operations shmem_fs_context_ops = {
    .free               = shmem_free_fc,
    .get_tree           = shmem_get_tree,
    .parse_monolithic   = shmem_parse_options,
    .parse_param        = shmem_parse_one,
    .reconfigure        = shmem_reconfigure,
};

int shmem_init_fs_context(struct fs_context *fc)
{
    struct shmem_options *ctx;

    ctx = kzalloc(sizeof(struct shmem_options), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->mode = 0777 | S_ISVTX;
    ctx->uid = current_fsuid();
    ctx->gid = current_fsgid();

    fc->fs_private = ctx;
    fc->ops = &shmem_fs_context_ops;
    return 0;
}
