// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/ext2/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#if 0
#include <linux/vfs.h>
#include <linux/seq_file.h>
#endif
#include <linux/mount.h>
#include <linux/log2.h>
//#include <linux/quotaops.h>
#include <linux/uaccess.h>
//#include <linux/dax.h>
//#include <linux/iversion.h>
#include "ext2.h"
#if 0
#include "xattr.h"
#include "acl.h"
#endif

static struct kmem_cache *ext2_inode_cachep;

void ext2_msg(struct super_block *sb, const char *prefix,
              const char *fmt, ...)
{
    struct va_format vaf;
    va_list args;

    va_start(args, fmt);

    vaf.fmt = fmt;
    vaf.va = &args;

    printk("%sEXT2-fs (%s): %pV\n", prefix, sb->s_id, &vaf);

    va_end(args);
}

static void ext2_clear_super_error(struct super_block *sb)
{
    struct buffer_head *sbh = EXT2_SB(sb)->s_sbh;

    if (buffer_write_io_error(sbh)) {
        /*
         * Oh, dear.  A previous attempt to write the
         * superblock failed.  This could happen because the
         * USB device was yanked out.  Or it could happen to
         * be a transient write error and maybe the block will
         * be remapped.  Nothing we can do but to retry the
         * write and hope for the best.
         */
        ext2_msg(sb, KERN_ERR,
                 "previous I/O error to superblock detected");
        clear_buffer_write_io_error(sbh);
        set_buffer_uptodate(sbh);
    }
}

void ext2_sync_super(struct super_block *sb,
                     struct ext2_super_block *es, int wait)
{
#if 0
    ext2_clear_super_error(sb);
    spin_lock(&EXT2_SB(sb)->s_lock);
    es->s_free_blocks_count = cpu_to_le32(ext2_count_free_blocks(sb));
    es->s_free_inodes_count = cpu_to_le32(ext2_count_free_inodes(sb));
    es->s_wtime = cpu_to_le32(ktime_get_real_seconds());
    /* unlock before we do IO */
    spin_unlock(&EXT2_SB(sb)->s_lock);
    mark_buffer_dirty(EXT2_SB(sb)->s_sbh);
    if (wait)
        sync_dirty_buffer(EXT2_SB(sb)->s_sbh);
#endif
    panic("%s: END!\n", __func__);
}

void ext2_error(struct super_block *sb, const char *function,
                const char *fmt, ...)
{
    struct va_format vaf;
    va_list args;
    struct ext2_sb_info *sbi = EXT2_SB(sb);
    struct ext2_super_block *es = sbi->s_es;

    if (!sb_rdonly(sb)) {
        spin_lock(&sbi->s_lock);
        sbi->s_mount_state |= EXT2_ERROR_FS;
        es->s_state |= cpu_to_le16(EXT2_ERROR_FS);
        spin_unlock(&sbi->s_lock);
        ext2_sync_super(sb, es, 1);
    }

    va_start(args, fmt);

    vaf.fmt = fmt;
    vaf.va = &args;

    printk(KERN_CRIT "EXT2-fs (%s): error: %s: %pV\n",
           sb->s_id, function, &vaf);

    va_end(args);

    if (test_opt(sb, ERRORS_PANIC))
        panic("EXT2-fs: panic from previous error\n");
    if (!sb_rdonly(sb) && test_opt(sb, ERRORS_RO)) {
        ext2_msg(sb, KERN_CRIT,
                 "error: remounting filesystem read-only");
        sb->s_flags |= SB_RDONLY;
    }
}

static void init_once(void *foo)
{
    struct ext2_inode_info *ei = (struct ext2_inode_info *) foo;

    rwlock_init(&ei->i_meta_lock);
    mutex_init(&ei->truncate_mutex);
    inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
    ext2_inode_cachep =
        kmem_cache_create_usercopy("ext2_inode_cache",
                                   sizeof(struct ext2_inode_info), 0,
                                   (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD|
                                    SLAB_ACCOUNT),
                                   offsetof(struct ext2_inode_info, i_data),
                                   sizeof_field(struct ext2_inode_info, i_data),
                                   init_once);
    if (ext2_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void)
{
    /*
     * Make sure all delayed rcu free inodes are flushed before we
     * destroy cache.
     */
    //rcu_barrier();
    kmem_cache_destroy(ext2_inode_cachep);
}

static unsigned long get_sb_block(void **data)
{
    unsigned long sb_block;
    char *options = (char *) *data;

    if (!options || strncmp(options, "sb=", 3) != 0)
        return 1;   /* Default location */

    panic("%s: END!\n", __func__);
}

static int parse_options(char *options, struct super_block *sb,
                         struct ext2_mount_options *opts)
{
    char *p;
    substring_t args[MAX_OPT_ARGS];
    int option;
    kuid_t uid;
    kgid_t gid;

    if (!options)
        return 1;

    panic("%s: END!\n", __func__);
}

/*
 * Maximal file size.  There is a direct, and {,double-,triple-}indirect
 * block limit, and also a limit of (2^32 - 1) 512-byte sectors in i_blocks.
 * We need to be 1 filesystem block less than the 2^32 sector limit.
 */
static loff_t ext2_max_size(int bits)
{
    loff_t res = EXT2_NDIR_BLOCKS;
    int meta_blocks;
    unsigned int upper_limit;
    unsigned int ppb = 1 << (bits-2);

    /* This is calculated to be the largest file size for a
     * dense, file such that the total number of
     * sectors in the file, including data and all indirect blocks,
     * does not exceed 2^32 -1
     * __u32 i_blocks representing the total number of
     * 512 bytes blocks of the file
     */
    upper_limit = (1LL << 32) - 1;

    /* total blocks in file system block size */
    upper_limit >>= (bits - 9);

    /* Compute how many blocks we can address by block tree */
    res += 1LL << (bits-2);
    res += 1LL << (2*(bits-2));
    res += 1LL << (3*(bits-2));
    /* Compute how many metadata blocks are needed */
    meta_blocks = 1;
    meta_blocks += 1 + ppb;
    meta_blocks += 1 + ppb + ppb * ppb;
    /* Does block tree limit file size? */
    if (res + meta_blocks <= upper_limit)
        goto check_lfs;

    res = upper_limit;
    /* How many metadata blocks are needed for addressing upper_limit? */
    upper_limit -= EXT2_NDIR_BLOCKS;
    /* indirect blocks */
    meta_blocks = 1;
    upper_limit -= ppb;
    /* double indirect blocks */
    if (upper_limit < ppb * ppb) {
        meta_blocks += 1 + DIV_ROUND_UP(upper_limit, ppb);
        res -= meta_blocks;
        goto check_lfs;
    }
    meta_blocks += 1 + ppb;
    upper_limit -= ppb * ppb;
    /* tripple indirect blocks for the rest */
    meta_blocks += 1 + DIV_ROUND_UP(upper_limit, ppb) +
        DIV_ROUND_UP(upper_limit, ppb*ppb);
    res -= meta_blocks;

 check_lfs:
    res <<= bits;
    if (res > MAX_LFS_FILESIZE)
        res = MAX_LFS_FILESIZE;

    return res;
}

static unsigned long descriptor_loc(struct super_block *sb,
                                    unsigned long logic_sb_block,
                                    int nr)
{
    struct ext2_sb_info *sbi = EXT2_SB(sb);
    unsigned long bg, first_meta_bg;

    first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

    if (!EXT2_HAS_INCOMPAT_FEATURE(sb, EXT2_FEATURE_INCOMPAT_META_BG) ||
        nr < first_meta_bg)
        return (logic_sb_block + nr + 1);
#if 0
    bg = sbi->s_desc_per_block * nr;

    return ext2_group_first_block_no(sb, bg) + ext2_bg_has_super(sb, bg);
#endif
    panic("%s: END!\n", __func__);
}

static int ext2_check_descriptors(struct super_block *sb)
{
    int i;
    struct ext2_sb_info *sbi = EXT2_SB(sb);

    for (i = 0; i < sbi->s_groups_count; i++) {
        struct ext2_group_desc *gdp = ext2_get_group_desc(sb, i, NULL);
        ext2_fsblk_t first_block = ext2_group_first_block_no(sb, i);
        ext2_fsblk_t last_block = ext2_group_last_block_no(sb, i);

        if (le32_to_cpu(gdp->bg_block_bitmap) < first_block ||
            le32_to_cpu(gdp->bg_block_bitmap) > last_block) {
            ext2_error(sb, "ext2_check_descriptors",
                       "Block bitmap for group %d not in group (block %lu)!",
                       i, (unsigned long) le32_to_cpu(gdp->bg_block_bitmap));
            return 0;
        }
        if (le32_to_cpu(gdp->bg_inode_bitmap) < first_block ||
            le32_to_cpu(gdp->bg_inode_bitmap) > last_block) {
            ext2_error(sb, "ext2_check_descriptors",
                       "Inode bitmap for group %d not in group (block %lu)!",
                       i, (unsigned long) le32_to_cpu(gdp->bg_inode_bitmap));
            return 0;
        }
        if (le32_to_cpu(gdp->bg_inode_table) < first_block ||
            le32_to_cpu(gdp->bg_inode_table) + sbi->s_itb_per_group - 1 >
            last_block) {
            ext2_error(sb, "ext2_check_descriptors",
                       "Inode table for group %d not in group (block %lu)!",
                       i, (unsigned long) le32_to_cpu(gdp->bg_inode_table));
            return 0;
        }
    }
    return 1;
}

static struct inode *ext2_alloc_inode(struct super_block *sb)
{
    struct ext2_inode_info *ei;
    ei = alloc_inode_sb(sb, ext2_inode_cachep, GFP_KERNEL);
    if (!ei)
        return NULL;
    ei->i_block_alloc_info = NULL;
    //inode_set_iversion(&ei->vfs_inode, 1);

    return &ei->vfs_inode;
}

static void ext2_free_in_core_inode(struct inode *inode)
{
    kmem_cache_free(ext2_inode_cachep, EXT2_I(inode));
}

static void ext2_put_super(struct super_block *sb)
{
    panic("%s: END!\n", __func__);
}

/*
 * In the second extended file system, it is not necessary to
 * write the super block since we use a mapping of the
 * disk super block in a buffer.
 *
 * However, this function is still used to set the fs valid
 * flags to 0.  We need to set this flag to 0 since the fs
 * may have been checked while mounted and e2fsck may have
 * set s_state to EXT2_VALID_FS after some corrections.
 */
static int ext2_sync_fs(struct super_block *sb, int wait)
{
    panic("%s: END!\n", __func__);
}

static int ext2_show_options(struct seq_file *seq, struct dentry *root)
{
    panic("%s: END!\n", __func__);
}

static int ext2_remount(struct super_block * sb, int * flags, char * data)
{
    panic("%s: END!\n", __func__);
}

static int ext2_statfs(struct dentry * dentry, struct kstatfs * buf)
{
    panic("%s: END!\n", __func__);
}

static int ext2_freeze(struct super_block *sb)
{
    panic("%s: END!\n", __func__);
}

static int ext2_unfreeze(struct super_block *sb)
{
#if 0
    /* Just write sb to clear EXT2_VALID_FS flag */
    ext2_write_super(sb);

    return 0;
#endif
    panic("%s: END!\n", __func__);
}

static const struct super_operations ext2_sops = {
    .alloc_inode    = ext2_alloc_inode,
    .free_inode     = ext2_free_in_core_inode,
    .write_inode    = ext2_write_inode,
    .evict_inode    = ext2_evict_inode,
    .put_super      = ext2_put_super,
    .sync_fs        = ext2_sync_fs,
    .freeze_fs      = ext2_freeze,
    .unfreeze_fs    = ext2_unfreeze,
    .statfs         = ext2_statfs,
    .remount_fs     = ext2_remount,
    .show_options   = ext2_show_options,
};

static int ext2_setup_super(struct super_block *sb,
                            struct ext2_super_block *es,
                            int read_only)
{
    int res = 0;
    struct ext2_sb_info *sbi = EXT2_SB(sb);

    if (le32_to_cpu(es->s_rev_level) > EXT2_MAX_SUPP_REV) {
        ext2_msg(sb, KERN_ERR,
                 "error: revision level too high, forcing read-only mode");
        res = SB_RDONLY;
    }
    if (read_only)
        return res;
    if (!(sbi->s_mount_state & EXT2_VALID_FS))
        ext2_msg(sb, KERN_WARNING,
                 "warning: mounting unchecked fs, "
                 "running e2fsck is recommended");
    else if ((sbi->s_mount_state & EXT2_ERROR_FS))
        ext2_msg(sb, KERN_WARNING,
                 "warning: mounting fs with errors, "
                 "running e2fsck is recommended");
    else if ((__s16) le16_to_cpu(es->s_max_mnt_count) >= 0 &&
             le16_to_cpu(es->s_mnt_count) >=
             (unsigned short) (__s16) le16_to_cpu(es->s_max_mnt_count))
        ext2_msg(sb, KERN_WARNING,
                 "warning: maximal mount count reached, "
                 "running e2fsck is recommended");
#if 0
    else if (le32_to_cpu(es->s_checkinterval) &&
             (le32_to_cpu(es->s_lastcheck) +
              le32_to_cpu(es->s_checkinterval) <= ktime_get_real_seconds()))
        ext2_msg(sb, KERN_WARNING,
                 "warning: checktime reached, "
                 "running e2fsck is recommended");
#endif

    if (!le16_to_cpu(es->s_max_mnt_count))
        es->s_max_mnt_count = cpu_to_le16(EXT2_DFL_MAX_MNT_COUNT);
    le16_add_cpu(&es->s_mnt_count, 1);
    if (test_opt(sb, DEBUG))
        ext2_msg(sb, KERN_INFO, "%s, %s, bs=%lu, fs=%lu, gc=%lu, "
                 "bpg=%lu, ipg=%lu, mo=%04lx]",
                 EXT2FS_VERSION, EXT2FS_DATE, sb->s_blocksize,
                 sbi->s_frag_size,
                 sbi->s_groups_count,
                 EXT2_BLOCKS_PER_GROUP(sb),
                 EXT2_INODES_PER_GROUP(sb),
                 sbi->s_mount_opt);
    panic("%s: END!\n", __func__);
    return res;
}

static void ext2_write_super(struct super_block *sb)
{
    if (!sb_rdonly(sb))
        ext2_sync_fs(sb, 1);
}

static int ext2_fill_super(struct super_block *sb, void *data, int silent)
{
    struct buffer_head *bh;
    struct ext2_sb_info *sbi;
    struct ext2_super_block *es;
    struct inode *root;
    unsigned long block;
    unsigned long sb_block = get_sb_block(&data);
    unsigned long logic_sb_block;
    unsigned long offset = 0;
    unsigned long def_mount_opts;
    long ret = -ENOMEM;
    int blocksize = BLOCK_SIZE;
    int db_count;
    int i, j;
    __le32 features;
    int err;
    struct ext2_mount_options opts;

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    sbi->s_blockgroup_lock =
        kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
    if (!sbi->s_blockgroup_lock) {
        kfree(sbi);
        return -ENOMEM;
    }
    sb->s_fs_info = sbi;
    sbi->s_sb_block = sb_block;
    sbi->s_daxdev = NULL;

    spin_lock_init(&sbi->s_lock);
    ret = -EINVAL;

    /*
     * See what the current blocksize for the device is, and
     * use that as the blocksize.  Otherwise (or if the blocksize
     * is smaller than the default) use the default.
     * This is important for devices that have a hardware
     * sectorsize that is larger than the default.
     */
    blocksize = sb_min_blocksize(sb, BLOCK_SIZE);
    if (!blocksize) {
        ext2_msg(sb, KERN_ERR, "error: unable to set blocksize");
        goto failed_sbi;
    }

    /*
     * If the superblock doesn't start on a hardware sector boundary,
     * calculate the offset.
     */
    if (blocksize != BLOCK_SIZE) {
        logic_sb_block = (sb_block*BLOCK_SIZE) / blocksize;
        offset = (sb_block*BLOCK_SIZE) % blocksize;
    } else {
        logic_sb_block = sb_block;
    }

    pr_info("%s: before sb_bread !\n", __func__);
    if (!(bh = sb_bread(sb, logic_sb_block))) {
        ext2_msg(sb, KERN_ERR, "error: unable to read superblock");
        goto failed_sbi;
    }
    pr_info("%s: after sb_bread bh(%lx) (%lx) !\n", __func__, bh, bh->b_page);
    /*
     * Note: s_es must be initialized as soon as possible because
     *       some ext2 macro-instructions depend on its value
     */
    es = (struct ext2_super_block *) (((char *)bh->b_data) + offset);
    sbi->s_es = es;
    sb->s_magic = le16_to_cpu(es->s_magic);

    if (sb->s_magic != EXT2_SUPER_MAGIC)
        goto cantfind_ext2;

    opts.s_mount_opt = 0;
    /* Set defaults before we parse the mount options */
    def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
    if (def_mount_opts & EXT2_DEFM_DEBUG)
        set_opt(opts.s_mount_opt, DEBUG);
    if (def_mount_opts & EXT2_DEFM_BSDGROUPS)
        set_opt(opts.s_mount_opt, GRPID);
    if (def_mount_opts & EXT2_DEFM_UID16)
        set_opt(opts.s_mount_opt, NO_UID32);

    if (le16_to_cpu(sbi->s_es->s_errors) == EXT2_ERRORS_PANIC)
        set_opt(opts.s_mount_opt, ERRORS_PANIC);
    else if (le16_to_cpu(sbi->s_es->s_errors) == EXT2_ERRORS_CONTINUE)
        set_opt(opts.s_mount_opt, ERRORS_CONT);
    else
        set_opt(opts.s_mount_opt, ERRORS_RO);

#if 0
    opts.s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
    opts.s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
#endif

    set_opt(opts.s_mount_opt, RESERVATION);

    if (!parse_options((char *) data, sb, &opts))
        goto failed_mount;

    sbi->s_mount_opt = opts.s_mount_opt;
    sbi->s_resuid = opts.s_resuid;
    sbi->s_resgid = opts.s_resgid;

    sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
        (test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);
    sb->s_iflags |= SB_I_CGROUPWB;

    if (le32_to_cpu(es->s_rev_level) == EXT2_GOOD_OLD_REV &&
        (EXT2_HAS_COMPAT_FEATURE(sb, ~0U) ||
         EXT2_HAS_RO_COMPAT_FEATURE(sb, ~0U) ||
         EXT2_HAS_INCOMPAT_FEATURE(sb, ~0U)))
        ext2_msg(sb, KERN_WARNING,
                 "warning: feature flags set on rev 0 fs, "
                 "running e2fsck is recommended");
    /*
     * Check feature flags regardless of the revision level, since we
     * previously didn't change the revision level when setting the flags,
     * so there is a chance incompat flags are set on a rev 0 filesystem.
     */
    features = EXT2_HAS_INCOMPAT_FEATURE(sb, ~EXT2_FEATURE_INCOMPAT_SUPP);
    if (features) {
        ext2_msg(sb, KERN_ERR,
                 "error: couldn't mount because of "
                 "unsupported optional features (%x)",
                 le32_to_cpu(features));
        goto failed_mount;
    }
    if (!sb_rdonly(sb) &&
        (features =
         EXT2_HAS_RO_COMPAT_FEATURE(sb, ~EXT2_FEATURE_RO_COMPAT_SUPP))){
        ext2_msg(sb, KERN_ERR,
                 "error: couldn't mount RDWR because of "
                 "unsupported optional features (%x)",
                 le32_to_cpu(features));
        goto failed_mount;
    }

    blocksize = BLOCK_SIZE << le32_to_cpu(sbi->s_es->s_log_block_size);

    if (test_opt(sb, DAX)) {
        if (!sbi->s_daxdev) {
            ext2_msg(sb, KERN_ERR,
                     "DAX unsupported by block device. Turning off DAX.");
            clear_opt(sbi->s_mount_opt, DAX);
        } else if (blocksize != PAGE_SIZE) {
            ext2_msg(sb, KERN_ERR, "unsupported blocksize for DAX\n");
            clear_opt(sbi->s_mount_opt, DAX);
        }
    }

    /* If the blocksize doesn't match, re-read the thing.. */
    if (sb->s_blocksize != blocksize) {
        brelse(bh);

        if (!sb_set_blocksize(sb, blocksize)) {
            ext2_msg(sb, KERN_ERR, "error: bad blocksize %d", blocksize);
            goto failed_sbi;
        }

        logic_sb_block = (sb_block*BLOCK_SIZE) / blocksize;
        offset = (sb_block*BLOCK_SIZE) % blocksize;
        bh = sb_bread(sb, logic_sb_block);
        if(!bh) {
            ext2_msg(sb, KERN_ERR, "error: couldn't read"
                     "superblock on 2nd try");
            goto failed_sbi;
        }
        es = (struct ext2_super_block *) (((char *)bh->b_data) + offset);
        sbi->s_es = es;
        if (es->s_magic != cpu_to_le16(EXT2_SUPER_MAGIC)) {
            ext2_msg(sb, KERN_ERR, "error: magic mismatch");
            goto failed_mount;
        }
    }

    sb->s_maxbytes = ext2_max_size(sb->s_blocksize_bits);
    sb->s_max_links = EXT2_LINK_MAX;
    sb->s_time_min = S32_MIN;
    sb->s_time_max = S32_MAX;

    if (le32_to_cpu(es->s_rev_level) == EXT2_GOOD_OLD_REV) {
        sbi->s_inode_size = EXT2_GOOD_OLD_INODE_SIZE;
        sbi->s_first_ino = EXT2_GOOD_OLD_FIRST_INO;
    } else {
        sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
        sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
        if ((sbi->s_inode_size < EXT2_GOOD_OLD_INODE_SIZE) ||
            !is_power_of_2(sbi->s_inode_size) ||
            (sbi->s_inode_size > blocksize)) {
            ext2_msg(sb, KERN_ERR, "error: unsupported inode size: %d",
                     sbi->s_inode_size);
            goto failed_mount;
        }
    }

    sbi->s_frag_size = EXT2_MIN_FRAG_SIZE << le32_to_cpu(es->s_log_frag_size);
    if (sbi->s_frag_size == 0)
        goto cantfind_ext2;
    sbi->s_frags_per_block = sb->s_blocksize / sbi->s_frag_size;

    sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
    sbi->s_frags_per_group = le32_to_cpu(es->s_frags_per_group);
    sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

    sbi->s_inodes_per_block = sb->s_blocksize / EXT2_INODE_SIZE(sb);
    if (sbi->s_inodes_per_block == 0 || sbi->s_inodes_per_group == 0)
        goto cantfind_ext2;
    sbi->s_itb_per_group = sbi->s_inodes_per_group / sbi->s_inodes_per_block;
    sbi->s_desc_per_block = sb->s_blocksize / sizeof (struct ext2_group_desc);
    sbi->s_sbh = bh;
    sbi->s_mount_state = le16_to_cpu(es->s_state);
    sbi->s_addr_per_block_bits = ilog2 (EXT2_ADDR_PER_BLOCK(sb));
    sbi->s_desc_per_block_bits = ilog2 (EXT2_DESC_PER_BLOCK(sb));

    if (sb->s_magic != EXT2_SUPER_MAGIC)
        goto cantfind_ext2;

    if (sb->s_blocksize != bh->b_size) {
        if (!silent)
            ext2_msg(sb, KERN_ERR, "error: unsupported blocksize");
        goto failed_mount;
    }

    if (sb->s_blocksize != sbi->s_frag_size) {
        ext2_msg(sb, KERN_ERR,
                 "error: fragsize %lu != blocksize %lu (not supported yet)",
                 sbi->s_frag_size, sb->s_blocksize);
        goto failed_mount;
    }

    if (sbi->s_blocks_per_group > sb->s_blocksize * 8) {
        ext2_msg(sb, KERN_ERR, "error: #blocks per group too big: %lu",
                 sbi->s_blocks_per_group);
        goto failed_mount;
    }
    if (sbi->s_frags_per_group > sb->s_blocksize * 8) {
        ext2_msg(sb, KERN_ERR, "error: #fragments per group too big: %lu",
                 sbi->s_frags_per_group);
        goto failed_mount;
    }
    if (sbi->s_inodes_per_group > sb->s_blocksize * 8) {
        ext2_msg(sb, KERN_ERR, "error: #inodes per group too big: %lu",
                 sbi->s_inodes_per_group);
        goto failed_mount;
    }

    if (EXT2_BLOCKS_PER_GROUP(sb) == 0)
        goto cantfind_ext2;
    sbi->s_groups_count =
        ((le32_to_cpu(es->s_blocks_count) -
          le32_to_cpu(es->s_first_data_block) - 1)
         / EXT2_BLOCKS_PER_GROUP(sb)) + 1;
    db_count = (sbi->s_groups_count + EXT2_DESC_PER_BLOCK(sb) - 1) /
        EXT2_DESC_PER_BLOCK(sb);

    sbi->s_group_desc =
        kmalloc_array(db_count, sizeof(struct buffer_head *), GFP_KERNEL);
    if (sbi->s_group_desc == NULL) {
        ret = -ENOMEM;
        ext2_msg(sb, KERN_ERR, "error: not enough memory");
        goto failed_mount;
    }
    bgl_lock_init(sbi->s_blockgroup_lock);
    sbi->s_debts = kcalloc(sbi->s_groups_count, sizeof(*sbi->s_debts),
                           GFP_KERNEL);
    if (!sbi->s_debts) {
        ret = -ENOMEM;
        ext2_msg(sb, KERN_ERR, "error: not enough memory");
        goto failed_mount_group_desc;
    }
    for (i = 0; i < db_count; i++) {
        block = descriptor_loc(sb, logic_sb_block, i);
        sbi->s_group_desc[i] = sb_bread(sb, block);
        if (!sbi->s_group_desc[i]) {
            for (j = 0; j < i; j++)
                brelse(sbi->s_group_desc[j]);
            ext2_msg(sb, KERN_ERR, "error: unable to read group descriptors");
            goto failed_mount_group_desc;
        }
    }
    if (!ext2_check_descriptors(sb)) {
        ext2_msg(sb, KERN_ERR, "group descriptors corrupted");
        goto failed_mount2;
    }
    sbi->s_gdb_count = db_count;
    //get_random_bytes(&sbi->s_next_generation, sizeof(u32));
    spin_lock_init(&sbi->s_next_gen_lock);

    /* per filesystem reservation list head & lock */
    spin_lock_init(&sbi->s_rsv_window_lock);
    sbi->s_rsv_window_root = RB_ROOT;
    /*
     * Add a single, static dummy reservation to the start of the
     * reservation window list --- it gives us a placeholder for
     * append-at-start-of-list which makes the allocation logic
     * _much_ simpler.
     */
    sbi->s_rsv_window_head.rsv_start = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;
    sbi->s_rsv_window_head.rsv_end = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;
    sbi->s_rsv_window_head.rsv_alloc_hit = 0;
    sbi->s_rsv_window_head.rsv_goal_size = 0;
    ext2_rsv_window_add(sb, &sbi->s_rsv_window_head);

    err = percpu_counter_init(&sbi->s_freeblocks_counter,
                              ext2_count_free_blocks(sb), GFP_KERNEL);
    if (!err) {
        err = percpu_counter_init(&sbi->s_freeinodes_counter,
                                  ext2_count_free_inodes(sb), GFP_KERNEL);
    }
    if (!err) {
        err = percpu_counter_init(&sbi->s_dirs_counter,
                                  ext2_count_dirs(sb), GFP_KERNEL);
    }
    if (err) {
        ret = err;
        ext2_msg(sb, KERN_ERR, "error: insufficient memory");
        goto failed_mount3;
    }

    /*
     * set up enough so that it can read an inode
     */
    sb->s_op = &ext2_sops;
#if 0
    sb->s_export_op = &ext2_export_ops;
    sb->s_xattr = ext2_xattr_handlers;
#endif

    root = ext2_iget(sb, EXT2_ROOT_INO);
    if (IS_ERR(root)) {
        ret = PTR_ERR(root);
        goto failed_mount3;
    }
    if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
        iput(root);
        ext2_msg(sb, KERN_ERR, "error: corrupt root inode, run e2fsck");
        goto failed_mount3;
    }

    sb->s_root = d_make_root(root);
    if (!sb->s_root) {
        ext2_msg(sb, KERN_ERR, "error: get root inode failed");
        ret = -ENOMEM;
        goto failed_mount3;
    }
    if (EXT2_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_HAS_JOURNAL))
        ext2_msg(sb, KERN_WARNING,
                 "warning: mounting ext3 filesystem as ext2");
    if (ext2_setup_super(sb, es, sb_rdonly(sb)))
        sb->s_flags |= SB_RDONLY;
    ext2_write_super(sb);
    return 0;

 cantfind_ext2:
    if (!silent)
        ext2_msg(sb, KERN_ERR,
                 "error: can't find an ext2 filesystem on dev %s.",
                 sb->s_id);
    goto failed_mount;
 failed_mount3:
    //ext2_xattr_destroy_cache(sbi->s_ea_block_cache);
    percpu_counter_destroy(&sbi->s_freeblocks_counter);
    percpu_counter_destroy(&sbi->s_freeinodes_counter);
    percpu_counter_destroy(&sbi->s_dirs_counter);
 failed_mount2:
    for (i = 0; i < db_count; i++)
        brelse(sbi->s_group_desc[i]);
 failed_mount_group_desc:
    kfree(sbi->s_group_desc);
    kfree(sbi->s_debts);
 failed_mount:
    brelse(bh);
 failed_sbi:
    sb->s_fs_info = NULL;
    kfree(sbi->s_blockgroup_lock);
    kfree(sbi);
    return ret;
}

static struct dentry *ext2_mount(struct file_system_type *fs_type,
                                 int flags, const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, ext2_fill_super);
}

static struct file_system_type ext2_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "ext2",
    .mount      = ext2_mount,
    .kill_sb    = kill_block_super,
    .fs_flags   = FS_REQUIRES_DEV,
};

static int __init init_ext2_fs(void)
{
    int err;

    err = init_inodecache();
    if (err)
        return err;
    err = register_filesystem(&ext2_fs_type);
    if (err)
        goto out;
    return 0;
out:
    destroy_inodecache();
    return err;
}

static void __exit exit_ext2_fs(void)
{
    unregister_filesystem(&ext2_fs_type);
    destroy_inodecache();
}

module_init(init_ext2_fs)
module_exit(exit_ext2_fs)
