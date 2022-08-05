/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */
#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <linux/rbtree.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/spinlock_types.h>

/*
 * File system states
 */
#define EXT2_VALID_FS           0x0001  /* Unmounted cleanly */
#define EXT2_ERROR_FS           0x0002  /* Errors detected */
#define EFSCORRUPTED            EUCLEAN /* Filesystem is corrupted */

/* data type for filesystem-wide blocks number */
typedef unsigned long ext2_fsblk_t;

struct ext2_reserve_window {
    ext2_fsblk_t        _rsv_start; /* First byte reserved */
    ext2_fsblk_t        _rsv_end;   /* Last byte reserved or 0 */
};

struct ext2_reserve_window_node {
    struct rb_node  rsv_node;
    __u32           rsv_goal_size;
    __u32           rsv_alloc_hit;
    struct ext2_reserve_window  rsv_window;
};

#define rsv_start rsv_window._rsv_start
#define rsv_end rsv_window._rsv_end

/*
 * Constants relative to the data blocks
 */
#define EXT2_NDIR_BLOCKS        12
#define EXT2_IND_BLOCK          EXT2_NDIR_BLOCKS
#define EXT2_DIND_BLOCK         (EXT2_IND_BLOCK + 1)
#define EXT2_TIND_BLOCK         (EXT2_DIND_BLOCK + 1)
#define EXT2_N_BLOCKS           (EXT2_TIND_BLOCK + 1)

/*
 * Structure of an inode on the disk
 */
struct ext2_inode {
    __le16  i_mode;     /* File mode */
    __le16  i_uid;      /* Low 16 bits of Owner Uid */
    __le32  i_size;     /* Size in bytes */
    __le32  i_atime;    /* Access time */
    __le32  i_ctime;    /* Creation time */
    __le32  i_mtime;    /* Modification time */
    __le32  i_dtime;    /* Deletion Time */
    __le16  i_gid;      /* Low 16 bits of Group Id */
    __le16  i_links_count;  /* Links count */
    __le32  i_blocks;   /* Blocks count */
    __le32  i_flags;    /* File flags */
    union {
        struct {
            __le32  l_i_reserved1;
        } linux1;
        struct {
            __le32  h_i_translator;
        } hurd1;
        struct {
            __le32  m_i_reserved1;
        } masix1;
    } osd1;             /* OS dependent 1 */
    __le32  i_block[EXT2_N_BLOCKS];/* Pointers to blocks */
    __le32  i_generation;   /* File version (for NFS) */
    __le32  i_file_acl; /* File ACL */
    __le32  i_dir_acl;  /* Directory ACL */
    __le32  i_faddr;    /* Fragment address */
    union {
        struct {
            __u8    l_i_frag;   /* Fragment number */
            __u8    l_i_fsize;  /* Fragment size */
            __u16   i_pad1;
            __le16  l_i_uid_high;   /* these 2 fields    */
            __le16  l_i_gid_high;   /* were reserved2[0] */
            __u32   l_i_reserved2;
        } linux2;
        struct {
            __u8    h_i_frag;   /* Fragment number */
            __u8    h_i_fsize;  /* Fragment size */
            __le16  h_i_mode_high;
            __le16  h_i_uid_high;
            __le16  h_i_gid_high;
            __le32  h_i_author;
        } hurd2;
        struct {
            __u8    m_i_frag;   /* Fragment number */
            __u8    m_i_fsize;  /* Fragment size */
            __u16   m_pad1;
            __u32   m_i_reserved2[2];
        } masix2;
    } osd2;             /* OS dependent 2 */
};

#define i_size_high i_dir_acl

#define i_reserved1 osd1.linux1.l_i_reserved1
#define i_frag      osd2.linux2.l_i_frag
#define i_fsize     osd2.linux2.l_i_fsize
#define i_uid_low   i_uid
#define i_gid_low   i_gid
#define i_uid_high  osd2.linux2.l_i_uid_high
#define i_gid_high  osd2.linux2.l_i_gid_high
#define i_reserved2 osd2.linux2.l_i_reserved2

/*
 * second extended file system inode data in memory
 */
struct ext2_inode_info {
    __le32  i_data[15];
    __u32   i_flags;
    __u32   i_faddr;
    __u8    i_frag_no;
    __u8    i_frag_size;
    __u16   i_state;
    __u32   i_file_acl;
    __u32   i_dir_acl;
    __u32   i_dtime;

    /*
     * i_block_group is the number of the block group which contains
     * this file's inode.  Constant across the lifetime of the inode,
     * it is used for making block allocation decisions - we try to
     * place a file's data blocks near its inode block, and new inodes
     * near to their parent directory's inode.
     */
    __u32   i_block_group;

    /* block reservation info */
    struct ext2_block_alloc_info *i_block_alloc_info;

    __u32   i_dir_start_lookup;

    rwlock_t i_meta_lock;

    /*
     * truncate_mutex is for serialising ext2_truncate() against
     * ext2_getblock().  It also protects the internals of the inode's
     * reservation data structures: ext2_reserve_window and
     * ext2_reserve_window_node.
     */
    struct mutex truncate_mutex;
    struct inode    vfs_inode;
    struct list_head i_orphan;  /* unlinked but open inodes */
};

/*
 * second extended-fs super-block data in memory
 */
struct ext2_sb_info {
    unsigned long s_frag_size;  /* Size of a fragment in bytes */
    unsigned long s_frags_per_block;/* Number of fragments per block */
    unsigned long s_inodes_per_block;/* Number of inodes per block */
    unsigned long s_frags_per_group;/* Number of fragments in a group */
    unsigned long s_blocks_per_group;/* Number of blocks in a group */
    unsigned long s_inodes_per_group;/* Number of inodes in a group */
    unsigned long s_itb_per_group;  /* Number of inode table blocks per group */
    unsigned long s_gdb_count;  /* Number of group descriptor blocks */
    unsigned long s_desc_per_block; /* Number of group descriptors per block */
    unsigned long s_groups_count;   /* Number of groups in the fs */
    unsigned long s_overhead_last;  /* Last calculated overhead */
    unsigned long s_blocks_last;    /* Last seen block count */
    struct buffer_head * s_sbh; /* Buffer containing the super block */
    struct ext2_super_block * s_es; /* Pointer to the super block in the buffer */
    struct buffer_head ** s_group_desc;
    unsigned long  s_mount_opt;
    unsigned long s_sb_block;
    kuid_t s_resuid;
    kgid_t s_resgid;
    unsigned short s_mount_state;
    unsigned short s_pad;
    int s_addr_per_block_bits;
    int s_desc_per_block_bits;
    int s_inode_size;
    int s_first_ino;
    spinlock_t s_next_gen_lock;
    u32 s_next_generation;
    unsigned long s_dir_count;
    u8 *s_debts;
    struct percpu_counter s_freeblocks_counter;
    struct percpu_counter s_freeinodes_counter;
    struct percpu_counter s_dirs_counter;
    struct blockgroup_lock *s_blockgroup_lock;
    /* root of the per fs reservation window tree */
    spinlock_t s_rsv_window_lock;
    struct rb_root s_rsv_window_root;
    struct ext2_reserve_window_node s_rsv_window_head;
    /*
     * s_lock protects against concurrent modifications of s_mount_state,
     * s_blocks_last, s_overhead_last and the content of superblock's
     * buffer pointed to by sbi->s_es.
     *
     * Note: It is used in ext2_show_options() to provide a consistent view
     * of the mount options.
     */
    spinlock_t s_lock;
    struct mb_cache *s_ea_block_cache;
    struct dax_device *s_daxdev;
    u64 s_dax_part_off;
};

/*
 * Structure of the super block
 */
struct ext2_super_block {
    __le32  s_inodes_count;     /* Inodes count */
    __le32  s_blocks_count;     /* Blocks count */
    __le32  s_r_blocks_count;   /* Reserved blocks count */
    __le32  s_free_blocks_count;    /* Free blocks count */
    __le32  s_free_inodes_count;    /* Free inodes count */
    __le32  s_first_data_block; /* First Data Block */
    __le32  s_log_block_size;   /* Block size */
    __le32  s_log_frag_size;    /* Fragment size */
    __le32  s_blocks_per_group; /* # Blocks per group */
    __le32  s_frags_per_group;  /* # Fragments per group */
    __le32  s_inodes_per_group; /* # Inodes per group */
    __le32  s_mtime;        /* Mount time */
    __le32  s_wtime;        /* Write time */
    __le16  s_mnt_count;        /* Mount count */
    __le16  s_max_mnt_count;    /* Maximal mount count */
    __le16  s_magic;        /* Magic signature */
    __le16  s_state;        /* File system state */
    __le16  s_errors;       /* Behaviour when detecting errors */
    __le16  s_minor_rev_level;  /* minor revision level */
    __le32  s_lastcheck;        /* time of last check */
    __le32  s_checkinterval;    /* max. time between checks */
    __le32  s_creator_os;       /* OS */
    __le32  s_rev_level;        /* Revision level */
    __le16  s_def_resuid;       /* Default uid for reserved blocks */
    __le16  s_def_resgid;       /* Default gid for reserved blocks */
    /*
     * These fields are for EXT2_DYNAMIC_REV superblocks only.
     *
     * Note: the difference between the compatible feature set and
     * the incompatible feature set is that if there is a bit set
     * in the incompatible feature set that the kernel doesn't
     * know about, it should refuse to mount the filesystem.
     *
     * e2fsck's requirements are more strict; if it doesn't know
     * about a feature in either the compatible or incompatible
     * feature set, it must abort and not try to meddle with
     * things it doesn't understand...
     */
    __le32  s_first_ino;        /* First non-reserved inode */
    __le16   s_inode_size;      /* size of inode structure */
    __le16  s_block_group_nr;   /* block group # of this superblock */
    __le32  s_feature_compat;   /* compatible feature set */
    __le32  s_feature_incompat;     /* incompatible feature set */
    __le32  s_feature_ro_compat;    /* readonly-compatible feature set */
    __u8    s_uuid[16];     /* 128-bit uuid for volume */
    char    s_volume_name[16];  /* volume name */
    char    s_last_mounted[64];     /* directory where last mounted */
    __le32  s_algorithm_usage_bitmap; /* For compression */
    /*
     * Performance hints.  Directory preallocation should only
     * happen if the EXT2_COMPAT_PREALLOC flag is on.
     */
    __u8    s_prealloc_blocks;  /* Nr of blocks to try to preallocate*/
    __u8    s_prealloc_dir_blocks;  /* Nr to preallocate for dirs */
    __u16   s_padding1;
    /*
     * Journaling support valid if EXT3_FEATURE_COMPAT_HAS_JOURNAL set.
     */
    __u8    s_journal_uuid[16]; /* uuid of journal superblock */
    __u32   s_journal_inum;     /* inode number of journal file */
    __u32   s_journal_dev;      /* device number of journal file */
    __u32   s_last_orphan;      /* start of list of inodes to delete */
    __u32   s_hash_seed[4];     /* HTREE hash seed */
    __u8    s_def_hash_version; /* Default hash version to use */
    __u8    s_reserved_char_pad;
    __u16   s_reserved_word_pad;
    __le32  s_default_mount_opts;
    __le32  s_first_meta_bg;    /* First metablock block group */
    __u32   s_reserved[190];    /* Padding to the end of the block */
};

/*
 * ext2 mount options
 */
struct ext2_mount_options {
    unsigned long s_mount_opt;
    kuid_t s_resuid;
    kgid_t s_resgid;
};

/*
 * Mount flags
 */
#define EXT2_MOUNT_OLDALLOC     0x000002  /* Don't use the new Orlov allocator */
#define EXT2_MOUNT_GRPID        0x000004  /* Create files with directory's group */
#define EXT2_MOUNT_DEBUG        0x000008  /* Some debugging messages */
#define EXT2_MOUNT_ERRORS_CONT  0x000010  /* Continue on errors */
#define EXT2_MOUNT_ERRORS_RO    0x000020  /* Remount fs ro on errors */
#define EXT2_MOUNT_ERRORS_PANIC 0x000040  /* Panic on errors */
#define EXT2_MOUNT_MINIX_DF     0x000080  /* Mimics the Minix statfs */
#define EXT2_MOUNT_NOBH         0x000100  /* No buffer_heads */
#define EXT2_MOUNT_NO_UID32     0x000200  /* Disable 32-bit UIDs */
#define EXT2_MOUNT_XATTR_USER   0x004000  /* Extended user attributes */
#define EXT2_MOUNT_POSIX_ACL    0x008000  /* POSIX Access Control Lists */
#define EXT2_MOUNT_XIP          0x010000  /* Obsolete, use DAX */
#define EXT2_MOUNT_USRQUOTA     0x020000  /* user quota */
#define EXT2_MOUNT_GRPQUOTA     0x040000  /* group quota */
#define EXT2_MOUNT_RESERVATION  0x080000  /* Preallocation */
#define EXT2_MOUNT_DAX          0x100000  /* Direct Access */

#define clear_opt(o, opt)   o &= ~EXT2_MOUNT_##opt
#define set_opt(o, opt)     o |= EXT2_MOUNT_##opt
#define test_opt(sb, opt)   (EXT2_SB(sb)->s_mount_opt & EXT2_MOUNT_##opt)

/*
 * Default mount options
 */
#define EXT2_DEFM_DEBUG     0x0001
#define EXT2_DEFM_BSDGROUPS 0x0002
#define EXT2_DEFM_XATTR_USER    0x0004
#define EXT2_DEFM_ACL       0x0008
#define EXT2_DEFM_UID16     0x0010

/*
 * Behaviour when detecting errors
 */
#define EXT2_ERRORS_CONTINUE    1   /* Continue execution */
#define EXT2_ERRORS_RO          2   /* Remount fs read-only */
#define EXT2_ERRORS_PANIC       3   /* Panic */
#define EXT2_ERRORS_DEFAULT     EXT2_ERRORS_CONTINUE

/*
 * Revision levels
 */
#define EXT2_GOOD_OLD_REV   0   /* The good old (original) format */
#define EXT2_DYNAMIC_REV    1   /* V2 format w/ dynamic inode sizes */

#define EXT2_CURRENT_REV    EXT2_GOOD_OLD_REV
#define EXT2_MAX_SUPP_REV   EXT2_DYNAMIC_REV

#define EXT2_GOOD_OLD_INODE_SIZE 128

static inline struct ext2_sb_info *EXT2_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

/*
 * Feature set definitions
 */

#define EXT2_HAS_COMPAT_FEATURE(sb,mask)            \
    ( EXT2_SB(sb)->s_es->s_feature_compat & cpu_to_le32(mask) )
#define EXT2_HAS_RO_COMPAT_FEATURE(sb,mask)         \
    ( EXT2_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(mask) )
#define EXT2_HAS_INCOMPAT_FEATURE(sb,mask)          \
    ( EXT2_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(mask) )
#define EXT2_SET_COMPAT_FEATURE(sb,mask)            \
    EXT2_SB(sb)->s_es->s_feature_compat |= cpu_to_le32(mask)
#define EXT2_SET_RO_COMPAT_FEATURE(sb,mask)         \
    EXT2_SB(sb)->s_es->s_feature_ro_compat |= cpu_to_le32(mask)
#define EXT2_SET_INCOMPAT_FEATURE(sb,mask)          \
    EXT2_SB(sb)->s_es->s_feature_incompat |= cpu_to_le32(mask)
#define EXT2_CLEAR_COMPAT_FEATURE(sb,mask)          \
    EXT2_SB(sb)->s_es->s_feature_compat &= ~cpu_to_le32(mask)
#define EXT2_CLEAR_RO_COMPAT_FEATURE(sb,mask)           \
    EXT2_SB(sb)->s_es->s_feature_ro_compat &= ~cpu_to_le32(mask)
#define EXT2_CLEAR_INCOMPAT_FEATURE(sb,mask)            \
    EXT2_SB(sb)->s_es->s_feature_incompat &= ~cpu_to_le32(mask)

#define EXT2_FEATURE_COMPAT_DIR_PREALLOC    0x0001
#define EXT2_FEATURE_COMPAT_IMAGIC_INODES   0x0002
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL     0x0004
#define EXT2_FEATURE_COMPAT_EXT_ATTR        0x0008
#define EXT2_FEATURE_COMPAT_RESIZE_INO      0x0010
#define EXT2_FEATURE_COMPAT_DIR_INDEX       0x0020
#define EXT2_FEATURE_COMPAT_ANY         0xffffffff

#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER 0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE   0x0002
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR    0x0004
#define EXT2_FEATURE_RO_COMPAT_ANY      0xffffffff

#define EXT2_FEATURE_INCOMPAT_COMPRESSION   0x0001
#define EXT2_FEATURE_INCOMPAT_FILETYPE      0x0002
#define EXT3_FEATURE_INCOMPAT_RECOVER       0x0004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV   0x0008
#define EXT2_FEATURE_INCOMPAT_META_BG       0x0010
#define EXT2_FEATURE_INCOMPAT_ANY       0xffffffff

#define EXT2_FEATURE_COMPAT_SUPP    EXT2_FEATURE_COMPAT_EXT_ATTR
#define EXT2_FEATURE_INCOMPAT_SUPP  (EXT2_FEATURE_INCOMPAT_FILETYPE | \
                                     EXT2_FEATURE_INCOMPAT_META_BG)
#define EXT2_FEATURE_RO_COMPAT_SUPP (EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER | \
                                     EXT2_FEATURE_RO_COMPAT_LARGE_FILE| \
                                     EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
#define EXT2_FEATURE_RO_COMPAT_UNSUPPORTED  ~EXT2_FEATURE_RO_COMPAT_SUPP
#define EXT2_FEATURE_INCOMPAT_UNSUPPORTED   ~EXT2_FEATURE_INCOMPAT_SUPP

/* First non-reserved inode for old ext2 filesystems */
#define EXT2_GOOD_OLD_FIRST_INO 11

/*
 * Macro-instructions used to manage fragments
 */
#define EXT2_MIN_FRAG_SIZE      1024
#define EXT2_MAX_FRAG_SIZE      4096
#define EXT2_MIN_FRAG_LOG_SIZE  10
#define EXT2_FRAG_SIZE(s)       (EXT2_SB(s)->s_frag_size)
#define EXT2_FRAGS_PER_BLOCK(s) (EXT2_SB(s)->s_frags_per_block)

/*
 * Macro-instructions used to manage several block sizes
 */
#define EXT2_MIN_BLOCK_SIZE     1024
#define EXT2_MAX_BLOCK_SIZE     4096
#define EXT2_MIN_BLOCK_LOG_SIZE 10
#define EXT2_BLOCK_SIZE(s)      ((s)->s_blocksize)
#define EXT2_ADDR_PER_BLOCK(s)  (EXT2_BLOCK_SIZE(s) / sizeof (__u32))
#define EXT2_BLOCK_SIZE_BITS(s) ((s)->s_blocksize_bits)
#define EXT2_ADDR_PER_BLOCK_BITS(s) (EXT2_SB(s)->s_addr_per_block_bits)
#define EXT2_INODE_SIZE(s)      (EXT2_SB(s)->s_inode_size)
#define EXT2_FIRST_INO(s)       (EXT2_SB(s)->s_first_ino)

/*
 * Structure of a blocks group descriptor
 */
struct ext2_group_desc
{
    __le32  bg_block_bitmap;        /* Blocks bitmap block */
    __le32  bg_inode_bitmap;        /* Inodes bitmap block */
    __le32  bg_inode_table;     /* Inodes table block */
    __le16  bg_free_blocks_count;   /* Free blocks count */
    __le16  bg_free_inodes_count;   /* Free inodes count */
    __le16  bg_used_dirs_count; /* Directories count */
    __le16  bg_pad;
    __le32  bg_reserved[3];
};

/*
 * Macro-instructions used to manage group descriptors
 */
#define EXT2_BLOCKS_PER_GROUP(s)    (EXT2_SB(s)->s_blocks_per_group)
#define EXT2_DESC_PER_BLOCK(s)      (EXT2_SB(s)->s_desc_per_block)
#define EXT2_INODES_PER_GROUP(s)    (EXT2_SB(s)->s_inodes_per_group)
#define EXT2_DESC_PER_BLOCK_BITS(s) (EXT2_SB(s)->s_desc_per_block_bits)

extern struct ext2_group_desc *
ext2_get_group_desc(struct super_block * sb,
                    unsigned int block_group,
                    struct buffer_head ** bh);

static inline ext2_fsblk_t
ext2_group_first_block_no(struct super_block *sb, unsigned long group_no)
{
    return group_no * (ext2_fsblk_t)EXT2_BLOCKS_PER_GROUP(sb) +
        le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
}

static inline ext2_fsblk_t
ext2_group_last_block_no(struct super_block *sb, unsigned long group_no)
{
    struct ext2_sb_info *sbi = EXT2_SB(sb);

    if (group_no == sbi->s_groups_count - 1)
        return le32_to_cpu(sbi->s_es->s_blocks_count) - 1;
    else
        return ext2_group_first_block_no(sb, group_no) +
            EXT2_BLOCKS_PER_GROUP(sb) - 1;
}

extern unsigned long ext2_count_free_blocks(struct super_block *);
extern unsigned long ext2_count_dirs(struct super_block *);

extern struct inode *
ext2_new_inode (struct inode *, umode_t, const struct qstr *);
extern void ext2_free_inode(struct inode *);
extern unsigned long ext2_count_free_inodes(struct super_block *);
extern unsigned long ext2_count_free(struct buffer_head *, unsigned);

extern void ext2_rsv_window_add(struct super_block *sb,
                                struct ext2_reserve_window_node *rsv);

/*
 * Define EXT2_RESERVATION to reserve data blocks for expanding files
 */
#define EXT2_DEFAULT_RESERVE_BLOCKS         8
/*max window size: 1024(direct blocks) + 3([t,d]indirect blocks) */
#define EXT2_MAX_RESERVE_BLOCKS             1027
#define EXT2_RESERVE_WINDOW_NOT_ALLOCATED   0
/*
 * The second extended file system version
 */
#define EXT2FS_DATE     "95/08/09"
#define EXT2FS_VERSION  "0.5b"

/*
 * Special inode numbers
 */
#define EXT2_BAD_INO         1  /* Bad blocks inode */
#define EXT2_ROOT_INO        2  /* Root inode */
#define EXT2_BOOT_LOADER_INO 5  /* Boot loader inode */
#define EXT2_UNDEL_DIR_INO   6  /* Undelete directory inode */

extern struct inode *ext2_iget(struct super_block *, unsigned long);
extern int ext2_write_inode(struct inode *, struct writeback_control *);
extern void ext2_evict_inode(struct inode *);
extern int ext2_get_block(struct inode *, sector_t, struct buffer_head *, int);
extern int ext2_setattr(struct user_namespace *, struct dentry *,
                        struct iattr *);
extern int ext2_getattr(struct user_namespace *, const struct path *,
                        struct kstat *, u32, unsigned int);

extern int ext2_write_inode (struct inode *, struct writeback_control *);
extern void ext2_evict_inode(struct inode *);

/*
 * Ok, these declarations are also in <linux/kernel.h> but none of the
 * ext2 source programs needs to include it so they are duplicated here.
 */
static inline struct ext2_inode_info *EXT2_I(struct inode *inode)
{
    return container_of(inode, struct ext2_inode_info, vfs_inode);
}

void ext2_error(struct super_block *, const char *, const char *, ...);

/*
 * Inode flags (GETFLAGS/SETFLAGS)
 */
#define EXT2_SECRM_FL           FS_SECRM_FL /* Secure deletion */
#define EXT2_UNRM_FL            FS_UNRM_FL  /* Undelete */
#define EXT2_COMPR_FL           FS_COMPR_FL /* Compress file */
#define EXT2_SYNC_FL            FS_SYNC_FL  /* Synchronous updates */
#define EXT2_IMMUTABLE_FL       FS_IMMUTABLE_FL /* Immutable file */
#define EXT2_APPEND_FL          FS_APPEND_FL    /* writes to file may only append */
#define EXT2_NODUMP_FL          FS_NODUMP_FL    /* do not dump file */
#define EXT2_NOATIME_FL         FS_NOATIME_FL   /* do not update atime */
/* Reserved for compression usage... */
#define EXT2_DIRTY_FL           FS_DIRTY_FL
#define EXT2_COMPRBLK_FL        FS_COMPRBLK_FL  /* One or more compressed clusters */
#define EXT2_NOCOMP_FL          FS_NOCOMP_FL    /* Don't compress */
#define EXT2_ECOMPR_FL          FS_ECOMPR_FL    /* Compression error */
/* End compression flags --- maybe not all used */
#define EXT2_BTREE_FL           FS_BTREE_FL /* btree format dir */
#define EXT2_INDEX_FL           FS_INDEX_FL /* hash-indexed directory */
#define EXT2_IMAGIC_FL          FS_IMAGIC_FL    /* AFS directory */
#define EXT2_JOURNAL_DATA_FL        FS_JOURNAL_DATA_FL /* Reserved for ext3 */
#define EXT2_NOTAIL_FL          FS_NOTAIL_FL    /* file tail should not be merged */
#define EXT2_DIRSYNC_FL         FS_DIRSYNC_FL   /* dirsync behaviour (directories only) */
#define EXT2_TOPDIR_FL          FS_TOPDIR_FL    /* Top of directory hierarchies*/
#define EXT2_RESERVED_FL        FS_RESERVED_FL  /* reserved for ext2 lib */

/* dir.c */
extern const struct file_operations ext2_dir_operations;

/* namei.c */
extern const struct inode_operations ext2_dir_inode_operations;
extern const struct inode_operations ext2_special_inode_operations;

extern int ext2_fileattr_get(struct dentry *dentry, struct fileattr *fa);
extern int ext2_fileattr_set(struct user_namespace *mnt_userns,
                             struct dentry *dentry, struct fileattr *fa);

extern long ext2_ioctl(struct file *, unsigned int, unsigned long);

/* file.c */
extern int ext2_fsync(struct file *file, loff_t start, loff_t end,
                      int datasync);

/*
 * Maximal mount counts between two filesystem checks
 */
#define EXT2_DFL_MAX_MNT_COUNT      20  /* Allow 20 mounts */
#define EXT2_DFL_CHECKINTERVAL      0   /* Don't use interval check */
