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
#include <linux/migrate.h>
#include <linux/highmem.h>
//#include <linux/seq_file.h>
#include <linux/magic.h>
#include <linux/fcntl.h>
#if 0
#include <linux/syscalls.h>
#include <uapi/linux/memfd.h>
#include <linux/userfaultfd_k.h>
#include <linux/rmap.h>
#endif
#include <linux/uuid.h>
#include <linux/uaccess.h>

#include "internal.h"

static const struct inode_operations shmem_dir_inode_operations;

/* Pretend that each entry is of this size in directory's i_size */
#define BOGO_DIRENT_SIZE 20

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

/*
 * Move the page from the page cache to the swap cache.
 */
static int shmem_writepage(struct page *page, struct writeback_control *wbc)
{
    panic("%s: END!\n", __func__);
}

static int
shmem_write_begin(struct file *file, struct address_space *mapping,
                  loff_t pos, unsigned len, unsigned flags,
                  struct page **pagep, void **fsdata)
{
    panic("%s: END!\n", __func__);
}

static int
shmem_write_end(struct file *file, struct address_space *mapping,
                loff_t pos, unsigned len, unsigned copied,
                struct page *page, void *fsdata)
{
    panic("%s: END!\n", __func__);
}

/* Keep the page in page cache instead of truncating it */
static int shmem_error_remove_page(struct address_space *mapping,
                                   struct page *page)
{
    return 0;
}

const struct address_space_operations shmem_aops = {
    .writepage      = shmem_writepage,
    .dirty_folio    = noop_dirty_folio,
    .write_begin    = shmem_write_begin,
    .write_end      = shmem_write_end,
    .migratepage    = migrate_page,
    .error_remove_page = shmem_error_remove_page,
};
EXPORT_SYMBOL(shmem_aops);

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

    free_percpu(sbinfo->ino_batch);
    percpu_counter_destroy(&sbinfo->used_blocks);
    kfree(sbinfo);
    sb->s_fs_info = NULL;
}

static struct kmem_cache *shmem_inode_cachep;

static struct inode *shmem_alloc_inode(struct super_block *sb)
{
    struct shmem_inode_info *info;
    info = alloc_inode_sb(sb, shmem_inode_cachep, GFP_KERNEL);
    if (!info)
        return NULL;
    return &info->vfs_inode;
}

static void shmem_free_in_core_inode(struct inode *inode)
{
    if (S_ISLNK(inode->i_mode))
        kfree(inode->i_link);
    kmem_cache_free(shmem_inode_cachep, SHMEM_I(inode));
}

static void shmem_destroy_inode(struct inode *inode)
{
}

static void shmem_evict_inode(struct inode *inode)
{
    panic("%s: END!\n", __func__);
}

static int shmem_getattr(struct user_namespace *mnt_userns,
                         const struct path *path, struct kstat *stat,
                         u32 request_mask, unsigned int query_flags)
{
    struct inode *inode = path->dentry->d_inode;
    struct shmem_inode_info *info = SHMEM_I(inode);

    panic("%s: END!\n", __func__);
}

static const struct inode_operations shmem_special_inode_operations = {
    .getattr    = shmem_getattr,
#if 0
    .listxattr  = shmem_listxattr,
    .setattr    = shmem_setattr,
    .set_acl    = simple_set_acl,
#endif
};

static const struct super_operations shmem_ops = {
    .alloc_inode    = shmem_alloc_inode,
    .free_inode     = shmem_free_in_core_inode,
    .destroy_inode  = shmem_destroy_inode,
#if 0
    .statfs         = shmem_statfs,
    .show_options   = shmem_show_options,
#endif
    .evict_inode    = shmem_evict_inode,
    .drop_inode     = generic_delete_inode,
    .put_super      = shmem_put_super,
};

static void shmem_init_inode(void *foo)
{
    struct shmem_inode_info *info = foo;
    inode_init_once(&info->vfs_inode);
}

static void shmem_init_inodecache(void)
{
    shmem_inode_cachep =
        kmem_cache_create("shmem_inode_cache",
                          sizeof(struct shmem_inode_info),
                          0, SLAB_PANIC|SLAB_ACCOUNT, shmem_init_inode);
}

static void shmem_destroy_inodecache(void)
{
    kmem_cache_destroy(shmem_inode_cachep);
}

/*
 * shmem_reserve_inode() performs bookkeeping to reserve a shmem inode, and
 * produces a novel ino for the newly allocated inode.
 *
 * It may also be called when making a hard link to permit the space needed by
 * each dentry. However, in that case, no new inode number is needed since that
 * internally draws from another pool of inode numbers (currently global
 * get_next_ino()). This case is indicated by passing NULL as inop.
 */
#define SHMEM_INO_BATCH 1024
static int shmem_reserve_inode(struct super_block *sb, ino_t *inop)
{
    struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
    ino_t ino;

    if (!(sb->s_flags & SB_KERNMOUNT)) {
        raw_spin_lock(&sbinfo->stat_lock);
        if (sbinfo->max_inodes) {
            if (!sbinfo->free_inodes) {
                raw_spin_unlock(&sbinfo->stat_lock);
                return -ENOSPC;
            }
            sbinfo->free_inodes--;
        }
        if (inop) {
            ino = sbinfo->next_ino++;
            if (unlikely(is_zero_ino(ino)))
                ino = sbinfo->next_ino++;
            if (unlikely(!sbinfo->full_inums && ino > UINT_MAX)) {
                /*
                 * Emulate get_next_ino uint wraparound for
                 * compatibility
                 */
                pr_warn("%s: inode number overflow on device %d, "
                        "consider using inode64 mount option\n",
                        __func__, MINOR(sb->s_dev));
                sbinfo->next_ino = 1;
                ino = sbinfo->next_ino++;
            }
            *inop = ino;
        }
        raw_spin_unlock(&sbinfo->stat_lock);
    } else if (inop) {
        /*
         * __shmem_file_setup, one of our callers, is lock-free: it
         * doesn't hold stat_lock in shmem_reserve_inode since
         * max_inodes is always 0, and is called from potentially
         * unknown contexts. As such, use a per-cpu batched allocator
         * which doesn't require the per-sb stat_lock unless we are at
         * the batch boundary.
         *
         * We don't need to worry about inode{32,64} since SB_KERNMOUNT
         * shmem mounts are not exposed to userspace, so we don't need
         * to worry about things like glibc compatibility.
         */
        ino_t *next_ino;

        next_ino = per_cpu_ptr(sbinfo->ino_batch, get_cpu());
        ino = *next_ino;
        if (unlikely(ino % SHMEM_INO_BATCH == 0)) {
            raw_spin_lock(&sbinfo->stat_lock);
            ino = sbinfo->next_ino;
            sbinfo->next_ino += SHMEM_INO_BATCH;
            raw_spin_unlock(&sbinfo->stat_lock);
            if (unlikely(is_zero_ino(ino)))
                ino++;
        }
        *inop = ino;
        *next_ino = ++ino;
        put_cpu();
    }

    return 0;
}

static void shmem_free_inode(struct super_block *sb)
{
    struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
    if (sbinfo->max_inodes) {
        raw_spin_lock(&sbinfo->stat_lock);
        sbinfo->free_inodes++;
        raw_spin_unlock(&sbinfo->stat_lock);
    }
}

static struct inode *
shmem_get_inode(struct super_block *sb, const struct inode *dir,
                umode_t mode, dev_t dev, unsigned long flags)
{
    struct inode *inode;
    struct shmem_inode_info *info;
    struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
    ino_t ino;

    if (shmem_reserve_inode(sb, &ino))
        return NULL;

    inode = new_inode(sb);
    if (inode) {
        inode->i_ino = ino;
        inode_init_owner(&init_user_ns, inode, dir, mode);
        inode->i_blocks = 0;
        inode->i_atime = inode->i_mtime = inode->i_ctime =
            current_time(inode);
        inode->i_generation = prandom_u32();
        info = SHMEM_I(inode);
        memset(info, 0, (char *)inode - (char *)info);
        spin_lock_init(&info->lock);
        atomic_set(&info->stop_eviction, 0);
        info->seals = F_SEAL_SEAL;
        info->flags = flags & VM_NORESERVE;
        info->i_crtime = inode->i_mtime;
        INIT_LIST_HEAD(&info->shrinklist);
        INIT_LIST_HEAD(&info->swaplist);
        //simple_xattrs_init(&info->xattrs);
        //cache_no_acl(inode);
        mapping_set_large_folios(inode->i_mapping);

        switch (mode & S_IFMT) {
        default:
            inode->i_op = &shmem_special_inode_operations;
            init_special_inode(inode, mode, dev);
            break;
        case S_IFREG:
#if 0
            inode->i_mapping->a_ops = &shmem_aops;
            inode->i_op = &shmem_inode_operations;
            inode->i_fop = &shmem_file_operations;
#endif
            panic("%s: S_IFREG.\n", __func__);
            break;
        case S_IFDIR:
            inc_nlink(inode);
            /* Some things misbehave if size == 0 on a directory */
            inode->i_size = 2 * BOGO_DIRENT_SIZE;
            inode->i_op = &shmem_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;
            break;
        case S_IFLNK:
            break;
        }
    } else {
        shmem_free_inode(sb);
    }
    return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
static int
shmem_mknod(struct user_namespace *mnt_userns, struct inode *dir,
        struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode *inode;
    int error = -ENOSPC;

    inode = shmem_get_inode(dir->i_sb, dir, mode, dev, VM_NORESERVE);
    if (inode) {
#if 0
        error = simple_acl_create(dir, inode);
        if (error)
            goto out_iput;
#endif
        error = 0;
        dir->i_size += BOGO_DIRENT_SIZE;
        dir->i_ctime = dir->i_mtime = current_time(dir);
        d_instantiate(dentry, inode);
        dget(dentry); /* Extra count - pin the dentry in core */
    }
    return error;
out_iput:
    iput(inode);
    return error;
}

static int shmem_create(struct user_namespace *mnt_userns, struct inode *dir,
                        struct dentry *dentry, umode_t mode, bool excl)
{
    return shmem_mknod(&init_user_ns, dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
static int shmem_link(struct dentry *old_dentry, struct inode *dir,
                      struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int shmem_unlink(struct inode *dir, struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int shmem_rmdir(struct inode *dir, struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int shmem_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                       struct dentry *dentry, umode_t mode)
{
    int error;

    if ((error = shmem_mknod(&init_user_ns, dir, dentry, mode | S_IFDIR, 0)))
        return error;
    inc_nlink(dir);
    return 0;
}

/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int shmem_rename2(struct user_namespace *mnt_userns,
                         struct inode *old_dir, struct dentry *old_dentry,
                         struct inode *new_dir, struct dentry *new_dentry,
                         unsigned int flags)
{
    panic("%s: END!\n", __func__);
}

static int
shmem_tmpfile(struct user_namespace *mnt_userns, struct inode *dir,
              struct dentry *dentry, umode_t mode)
{
    panic("%s: END!\n", __func__);
}

static int shmem_symlink(struct user_namespace *mnt_userns, struct inode *dir,
                         struct dentry *dentry, const char *symname)
{
    panic("%s: END!\n", __func__);
}

static const struct inode_operations shmem_dir_inode_operations = {
    .getattr    = shmem_getattr,
    .create     = shmem_create,
    .lookup     = simple_lookup,
    .link       = shmem_link,
    .unlink     = shmem_unlink,
    .symlink    = shmem_symlink,
    .mkdir      = shmem_mkdir,
    .rmdir      = shmem_rmdir,
    .mknod      = shmem_mknod,
    .rename     = shmem_rename2,
    .tmpfile    = shmem_tmpfile,
#if 0
    .listxattr  = shmem_listxattr,
#endif
#if 0
    .setattr    = shmem_setattr,
    .set_acl    = simple_set_acl,
#endif
};

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
        sbinfo->ino_batch = alloc_percpu(ino_t);
        if (!sbinfo->ino_batch)
            goto failed;
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

    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = TMPFS_MAGIC;
    sb->s_op = &shmem_ops;
    sb->s_time_gran = 1;
#if 0
    sb->s_xattr = shmem_xattr_handlers;
#endif
    sb->s_flags |= SB_POSIXACL;
    //uuid_gen(&sb->s_uuid);

    inode = shmem_get_inode(sb, NULL, S_IFDIR | sbinfo->mode, 0, VM_NORESERVE);
    if (!inode)
        goto failed;
    inode->i_uid = sbinfo->uid;
    inode->i_gid = sbinfo->gid;
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        goto failed;
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

unsigned long shmem_get_unmapped_area(struct file *file,
                      unsigned long uaddr, unsigned long len,
                      unsigned long pgoff, unsigned long flags)
{
    unsigned long (*get_area)(struct file *,
        unsigned long, unsigned long, unsigned long, unsigned long);
    unsigned long addr;
    unsigned long offset;
    unsigned long inflated_len;
    unsigned long inflated_addr;
    unsigned long inflated_offset;

    if (len > TASK_SIZE)
        return -ENOMEM;

    panic("%s: END!\n", __func__);
}

static struct file_system_type shmem_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "tmpfs",
    .init_fs_context = shmem_init_fs_context,
    .parameters = shmem_fs_parameters,
    .kill_sb    = kill_litter_super,
    .fs_flags   = FS_USERNS_MOUNT,
};

int __init shmem_init(void)
{
    int error;

    shmem_init_inodecache();

    error = register_filesystem(&shmem_fs_type);
    if (error) {
        pr_err("Could not register tmpfs\n");
        goto out2;
    }

    shm_mnt = kern_mount(&shmem_fs_type);
    if (IS_ERR(shm_mnt)) {
        error = PTR_ERR(shm_mnt);
        pr_err("Could not kern_mount tmpfs\n");
        goto out1;
    }

    return 0;

out1:
    unregister_filesystem(&shmem_fs_type);
out2:
    shmem_destroy_inodecache();
    shm_mnt = ERR_PTR(error);
    return error;
}
