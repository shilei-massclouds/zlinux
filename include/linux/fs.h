/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/linkage.h>
#if 0
#include <linux/wait_bit.h>
#include <linux/kdev_t.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/stat.h>
#endif
#include <linux/cache.h>
#include <linux/list.h>
#include <linux/list_lru.h>
#include <linux/llist.h>
#include <linux/radix-tree.h>
#include <linux/xarray.h>
#include <linux/rbtree.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/bug.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#if 0
#include <linux/capability.h>
#endif
#include <linux/mm_types.h>
#include <linux/semaphore.h>
#if 0
#include <linux/fcntl.h>
#include <linux/rculist_bl.h>
#endif
#include <linux/atomic.h>
#if 0
#include <linux/shrinker.h>
#include <linux/migrate_mode.h>
#endif
#include <linux/uidgid.h>
#include <linux/uuid.h>
#if 0
#include <linux/percpu-rwsem.h>
#include <linux/workqueue.h>
#include <linux/delayed_call.h>
#include <linux/errseq.h>
#include <linux/ioprio.h>
#include <linux/fs_types.h>
#include <linux/build_bug.h>
#endif
#include <linux/stddef.h>
#if 0
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/mnt_idmapping.h>
#endif
#include <linux/slab.h>

#include <asm/byteorder.h>
#if 0
#include <uapi/linux/fs.h>
#endif

struct backing_dev_info;
struct bdi_writeback;
struct bio;
struct io_comp_batch;
struct export_operations;
struct fiemap_extent_info;
struct hd_geometry;
struct iovec;
struct kiocb;
struct kobject;
struct pipe_inode_info;
struct poll_table_struct;
struct kstatfs;
struct vm_area_struct;
struct vfsmount;
struct cred;
struct swap_info_struct;
struct seq_file;
struct workqueue_struct;
struct iov_iter;
struct fscrypt_info;
struct fscrypt_operations;
struct fsverity_info;
struct fsverity_operations;
struct fs_context;
struct fs_parameter_spec;
struct fileattr;

/* sb->s_iflags */
#define SB_I_CGROUPWB   0x00000001  /* cgroup-aware writeback enabled */
#define SB_I_NOEXEC     0x00000002  /* Ignore executables on this fs */
#define SB_I_NODEV      0x00000004  /* Ignore devices on this fs */
#define SB_I_STABLE_WRITES 0x00000008   /* don't modify blks until WB is done */

/* sb->s_iflags to limit user namespace mounts */
#define SB_I_USERNS_VISIBLE     0x00000010 /* fstype already mounted */
#define SB_I_IMA_UNVERIFIABLE_SIGNATURE 0x00000020
#define SB_I_UNTRUSTED_MOUNTER  0x00000040

#define SB_I_SKIP_SYNC  0x00000100  /* Skip superblock at global sync */
#define SB_I_PERSB_BDI  0x00000200  /* has a per-sb bdi */
#define SB_I_TS_EXPIRY_WARNED 0x00000400 /* warned about timestamp range expiry */

/* These sb flags are internal to the kernel */
#define SB_SUBMOUNT (1<<26)
#define SB_FORCE    (1<<27)
#define SB_NOSEC    (1<<28)
#define SB_BORN     (1<<29)
#define SB_ACTIVE   (1<<30)
#define SB_NOUSER   (1<<31)

/*
 * sb->s_flags.  Note that these mirror the equivalent MS_* flags where
 * represented in both.
 */
#define SB_RDONLY       1  /* Mount read-only */
#define SB_NOSUID       2  /* Ignore suid and sgid bits */
#define SB_NODEV        4  /* Disallow access to device special files */
#define SB_NOEXEC       8  /* Disallow program execution */
#define SB_SYNCHRONOUS  16  /* Writes are synced at once */
#define SB_MANDLOCK     64  /* Allow mandatory locks on an FS */
#define SB_DIRSYNC      128 /* Directory modifications are synchronous */
#define SB_NOATIME      1024    /* Do not update access times. */
#define SB_NODIRATIME   2048    /* Do not update directory access times */
#define SB_SILENT       32768
#define SB_POSIXACL     (1<<16) /* VFS does not apply the umask */
#define SB_INLINECRYPT  (1<<17) /* Use blk-crypto for encrypted files */
#define SB_KERNMOUNT    (1<<22) /* this is a kern_mount call */
#define SB_I_VERSION    (1<<23) /* Update inode I_version field */
#define SB_LAZYTIME     (1<<25) /* Update the on-disk [acm]times lazily */

/* Possible states of 'frozen' field */
enum {
    SB_UNFROZEN = 0,        /* FS is unfrozen */
    SB_FREEZE_WRITE = 1,        /* Writes, dir ops, ioctls frozen */
    SB_FREEZE_PAGEFAULT = 2,    /* Page faults stopped as well */
    SB_FREEZE_FS = 3,       /* For internal FS use (e.g. to stop
                     * internal threads if needed) */
    SB_FREEZE_COMPLETE = 4,     /* ->freeze_fs finished successfully */
};

#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)

/*
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 */
struct inode {
    umode_t         i_mode;
    unsigned short  i_opflags;
    kuid_t          i_uid;
    kgid_t          i_gid;
    unsigned int    i_flags;

#if 0
    struct posix_acl    *i_acl;
    struct posix_acl    *i_default_acl;
#endif

#if 0
    const struct inode_operations   *i_op;
    struct super_block  *i_sb;
    struct address_space    *i_mapping;

    /* Stat data, not accessed from path walking */
    unsigned long       i_ino;
    /*
     * Filesystems may only read i_nlink directly.  They shall use the
     * following functions for modification:
     *
     *    (set|clear|inc|drop)_nlink
     *    inode_(inc|dec)_link_count
     */
    union {
        const unsigned int i_nlink;
        unsigned int __i_nlink;
    };
    dev_t           i_rdev;
    loff_t          i_size;
    struct timespec64   i_atime;
    struct timespec64   i_mtime;
    struct timespec64   i_ctime;
#endif
    spinlock_t          i_lock; /* i_blocks, i_bytes, maybe i_size */
    unsigned short      i_bytes;
    u8                  i_blkbits;
    u8                  i_write_hint;
    blkcnt_t            i_blocks;

    /* Misc */
    unsigned long       i_state;
#if 0
    struct rw_semaphore i_rwsem;
#endif

    unsigned long       dirtied_when;   /* jiffies of first dirtying */
    unsigned long       dirtied_time_when;

    struct hlist_node   i_hash;
    struct list_head    i_io_list;  /* backing dev IO list */
    struct list_head    i_lru;      /* inode LRU list */
    struct list_head    i_sb_list;
    struct list_head    i_wb_list;  /* backing dev writeback list */
    union {
        struct hlist_head   i_dentry;
        struct rcu_head     i_rcu;
    };
    atomic64_t      i_version;
    atomic64_t      i_sequence; /* see futex */
    atomic_t        i_count;
    atomic_t        i_dio_count;
    atomic_t        i_writecount;
#if 0
    atomic_t        i_readcount; /* struct files open RO */
#endif
#if 0
    union {
        const struct file_operations    *i_fop; /* former ->i_op->default_file_ops */
        void (*free_inode)(struct inode *);
    };
    struct file_lock_context    *i_flctx;
    struct address_space    i_data;
#endif
    struct list_head    i_devices;
#if 0
    union {
        struct pipe_inode_info  *i_pipe;
        struct cdev     *i_cdev;
        char            *i_link;
        unsigned        i_dir_seq;
    };
#endif

    __u32 i_generation;

#if 0
    __u32           i_fsnotify_mask; /* all events this inode cares about */
    struct fsnotify_mark_connector __rcu    *i_fsnotify_marks;
#endif

    void *i_private; /* fs or device private pointer */
} __randomize_layout;

struct super_block {
    struct list_head    s_list;     /* Keep this first */
    dev_t               s_dev;      /* search index; _not_ kdev_t */
    unsigned char       s_blocksize_bits;
    unsigned long       s_blocksize;
    loff_t              s_maxbytes; /* Max file size */
    //struct file_system_type *s_type;
    const struct super_operations   *s_op;
#if 0
    const struct dquot_operations   *dq_op;
    const struct quotactl_ops       *s_qcop;
    const struct export_operations  *s_export_op;
    unsigned long       s_flags;
    unsigned long       s_iflags;   /* internal SB_I_* flags */
    unsigned long       s_magic;
    struct dentry       *s_root;
    struct rw_semaphore s_umount;
    int         s_count;
    atomic_t        s_active;
    const struct xattr_handler **s_xattr;
    struct hlist_bl_head    s_roots;    /* alternate root dentries for NFS */
    struct list_head    s_mounts;   /* list of mounts; _not_ for fs use */
    struct block_device *s_bdev;
    struct backing_dev_info *s_bdi;
    struct mtd_info     *s_mtd;
    struct hlist_node   s_instances;
    unsigned int        s_quota_types;  /* Bitmask of supported quota types */
    struct quota_info   s_dquot;    /* Diskquota specific options */

    struct sb_writers   s_writers;
    /*
     * Keep s_fs_info, s_time_gran, s_fsnotify_mask, and
     * s_fsnotify_marks together for cache efficiency. They are frequently
     * accessed and rarely modified.
     */
    void            *s_fs_info; /* Filesystem private info */

    /* Granularity of c/m/atime in ns (cannot be worse than a second) */
    u32         s_time_gran;
    /* Time limits for c/m/atime in seconds */
    time64_t           s_time_min;
    time64_t           s_time_max;
#endif
#if 0
    __u32           s_fsnotify_mask;
    struct fsnotify_mark_connector __rcu    *s_fsnotify_marks;
#endif

    char            s_id[32];   /* Informational name */
    uuid_t          s_uuid;     /* UUID */

    unsigned int    s_max_links;
    fmode_t         s_mode;

    /*
     * The next field is for VFS *only*. No filesystems have any business
     * even looking at it. You had been warned.
     */
    struct mutex s_vfs_rename_mutex;    /* Kludge */

    /*
     * Filesystem subtype.  If non-empty the filesystem type field
     * in /proc/mounts will be "type.subtype"
     */
    const char *s_subtype;
#if 0
    const struct dentry_operations *s_d_op; /* default d_op for dentries */

    struct shrinker s_shrink;   /* per-sb shrinker handle */

    /* Number of inodes with nlink == 0 but still referenced */
    atomic_long_t s_remove_count;

    /*
     * Number of inode/mount/sb objects that are being watched, note that
     * inodes objects are currently double-accounted.
     */
    atomic_long_t s_fsnotify_connectors;

    /* Being remounted read-only */
    int s_readonly_remount;

    /* per-sb errseq_t for reporting writeback errors via syncfs */
    errseq_t s_wb_err;

    /* AIO completions deferred from interrupt context */
    struct workqueue_struct *s_dio_done_wq;
    struct hlist_head s_pins;

    /*
     * Owning user namespace and default context in which to
     * interpret filesystem uids, gids, quotas, device nodes,
     * xattrs and security labels.
     */
    struct user_namespace *s_user_ns;
#endif
    /*
     * The list_lru structure is essentially just a pointer to a table
     * of per-node lru lists, each of which has its own spinlock.
     * There is no need to put them into separate cachelines.
     */
    struct list_lru     s_dentry_lru;
    struct list_lru     s_inode_lru;
    struct rcu_head     rcu;
    //struct work_struct  destroy_work;

    struct mutex        s_sync_lock;    /* sync serialisation lock */

    /*
     * Indicates how deep in a filesystem stack this SB is
     */
    int s_stack_depth;

    /* s_inode_list_lock protects s_inodes */
    spinlock_t      s_inode_list_lock ____cacheline_aligned_in_smp;
    struct list_head    s_inodes;   /* all inodes */

    spinlock_t      s_inode_wblist_lock;
    struct list_head    s_inodes_wb;    /* writeback inodes */
} __randomize_layout;

struct super_operations {
    struct inode *(*alloc_inode)(struct super_block *sb);
    void (*destroy_inode)(struct inode *);
    void (*free_inode)(struct inode *);

    void (*dirty_inode) (struct inode *, int flags);
#if 0
    int (*write_inode) (struct inode *, struct writeback_control *wbc);
#endif
    int (*drop_inode) (struct inode *);
    void (*evict_inode) (struct inode *);
    void (*put_super) (struct super_block *);
    int (*sync_fs)(struct super_block *sb, int wait);
    int (*freeze_super) (struct super_block *);
    int (*freeze_fs) (struct super_block *);
    int (*thaw_super) (struct super_block *);
    int (*unfreeze_fs) (struct super_block *);
    int (*statfs) (struct dentry *, struct kstatfs *);
    int (*remount_fs) (struct super_block *, int *, char *);
    void (*umount_begin) (struct super_block *);

#if 0
    int (*show_options)(struct seq_file *, struct dentry *);
    int (*show_devname)(struct seq_file *, struct dentry *);
    int (*show_path)(struct seq_file *, struct dentry *);
    int (*show_stats)(struct seq_file *, struct dentry *);
    long (*nr_cached_objects)(struct super_block *, struct shrink_control *);
    long (*free_cached_objects)(struct super_block *, struct shrink_control *);
#endif
};

struct file_system_type {
    const char *name;
    int fs_flags;
#define FS_REQUIRES_DEV         1
#define FS_BINARY_MOUNTDATA     2
#define FS_HAS_SUBTYPE          4
#define FS_USERNS_MOUNT         8   /* Can be mounted by userns root */
#define FS_DISALLOW_NOTIFY_PERM 16  /* Disable fanotify permission events */
#define FS_ALLOW_IDMAP          32  /* FS has been updated to handle vfs idmappings. */
#define FS_RENAME_DOES_D_MOVE   32768   /* FS will handle d_move() during rename() internally. */
    int (*init_fs_context)(struct fs_context *);
    const struct fs_parameter_spec *parameters;
    struct dentry *(*mount) (struct file_system_type *, int,
                             const char *, void *);
    void (*kill_sb) (struct super_block *);
    struct module *owner;
    struct file_system_type *next;
    struct hlist_head fs_supers;

    struct lock_class_key s_lock_key;
    struct lock_class_key s_umount_key;
    struct lock_class_key s_vfs_rename_key;
    struct lock_class_key s_writers_key[SB_FREEZE_LEVELS];

    struct lock_class_key i_lock_key;
    struct lock_class_key i_mutex_key;
    struct lock_class_key invalidate_lock_key;
    struct lock_class_key i_mutex_dir_key;
};

extern struct inode *new_inode_pseudo(struct super_block *sb);
extern struct inode *new_inode(struct super_block *sb);

extern void inode_init_once(struct inode *);

void kill_anon_super(struct super_block *sb);

/*
 * This must be used for allocating filesystems specific inodes to set
 * up the inode reclaim context correctly.
 */
static inline void *
alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
{
    return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
}

extern int register_filesystem(struct file_system_type *);

extern void __init vfs_caches_init(void);

extern struct vfsmount *kern_mount(struct file_system_type *);

extern struct file_system_type *get_filesystem(struct file_system_type *fs);
extern void put_filesystem(struct file_system_type *fs);

#endif /* _LINUX_FS_H */
