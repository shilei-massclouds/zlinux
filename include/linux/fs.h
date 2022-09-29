/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/linkage.h>
#include <linux/dcache.h>
#include <linux/wait_bit.h>
#include <linux/kdev_t.h>
#include <linux/path.h>
#include <linux/stat.h>
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
#include <linux/fcntl.h>
#include <linux/rculist_bl.h>
#include <linux/atomic.h>
#include <linux/shrinker.h>
#include <linux/migrate_mode.h>
#include <linux/uidgid.h>
#include <linux/lockdep.h>
#include <linux/uuid.h>
#include <linux/percpu-rwsem.h>
#include <linux/delayed_call.h>
//#include <linux/workqueue.h>
#include <linux/ioprio.h>
//#include <linux/fs_types.h>
#include <linux/build_bug.h>
#include <linux/errseq.h>
#include <linux/stddef.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/mnt_idmapping.h>
#include <linux/slab.h>
#include <linux/time64.h>

#include <asm/byteorder.h>
#include <uapi/linux/fs.h>

/**
 * enum positive_aop_returns - aop return codes with specific semantics
 *
 * @AOP_WRITEPAGE_ACTIVATE: Informs the caller that page writeback has
 *              completed, that the page is still locked, and
 *              should be considered active.  The VM uses this hint
 *              to return the page to the active list -- it won't
 *              be a candidate for writeback again in the near
 *              future.  Other callers must be careful to unlock
 *              the page if they get this return.  Returned by
 *              writepage();
 *
 * @AOP_TRUNCATED_PAGE: The AOP method that was handed a locked page has
 *              unlocked it and the page might have been truncated.
 *              The caller should back up to acquiring a new page and
 *              trying again.  The aop will be taking reasonable
 *              precautions not to livelock.  If the caller held a page
 *              reference, it should drop it before retrying.  Returned
 *              by readpage().
 *
 * address_space_operation functions return these large constants to indicate
 * special semantics to the caller.  These are much larger than the bytes in a
 * page to allow for functions that return the number of bytes operated on in a
 * given page.
 */
enum positive_aop_returns {
    AOP_WRITEPAGE_ACTIVATE  = 0x80000,
    AOP_TRUNCATED_PAGE      = 0x80001,
};

#define AOP_FLAG_NOFS       0x0002 /* used by filesystem to direct
                                    * helper code (eg buffer layer)
                                    * to clear GFP_FS from alloc */

/* XArray tags, for tagging dirty and writeback pages in the pagecache. */
#define PAGECACHE_TAG_DIRTY     XA_MARK_0
#define PAGECACHE_TAG_WRITEBACK XA_MARK_1
#define PAGECACHE_TAG_TOWRITE   XA_MARK_2

#define MAX_LFS_FILESIZE    ((loff_t)LLONG_MAX)

#define IOP_FASTPERM    0x0001
#define IOP_LOOKUP      0x0002
#define IOP_NOFOLLOW    0x0004
#define IOP_XATTR       0x0008
#define IOP_DEFAULT_READLINK    0x0010

/*
 * flags in file.f_mode.  Note that FMODE_READ and FMODE_WRITE must correspond
 * to O_WRONLY and O_RDWR via the strange trick in do_dentry_open()
 */

/* file is open for reading */
#define FMODE_READ      ((__force fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE     ((__force fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK     ((__force fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD     ((__force fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE        ((__force fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      ((__force fmode_t)0x20)
/* File is opened with O_NDELAY (only set for block devices) */
#define FMODE_NDELAY        ((__force fmode_t)0x40)
/* File is opened with O_EXCL (only set for block devices) */
#define FMODE_EXCL      ((__force fmode_t)0x80)
/* File is opened using open(.., 3, ..) and is writeable only for ioctls
   (specialy hack for floppy.c) */
#define FMODE_WRITE_IOCTL   ((__force fmode_t)0x100)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH         ((__force fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH         ((__force fmode_t)0x400)

/*
 * Don't update ctime and mtime.
 *
 * Currently a special hack for the XFS open_by_handle ioctl, but we'll
 * hopefully graduate it to a proper O_CMTIME flag supported by open(2) soon.
 */
#define FMODE_NOCMTIME      ((__force fmode_t)0x800)

/* Expect random access pattern */
#define FMODE_RANDOM        ((__force fmode_t)0x1000)

/* File is huge (eg. /dev/mem): treat loff_t as unsigned */
#define FMODE_UNSIGNED_OFFSET   ((__force fmode_t)0x2000)

/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH      ((__force fmode_t)0x4000)

/* File needs atomic accesses to f_pos */
#define FMODE_ATOMIC_POS    ((__force fmode_t)0x8000)
/* Write access to underlying fs */
#define FMODE_WRITER        ((__force fmode_t)0x10000)
/* Has read method(s) */
#define FMODE_CAN_READ          ((__force fmode_t)0x20000)
/* Has write method(s) */
#define FMODE_CAN_WRITE         ((__force fmode_t)0x40000)

#define FMODE_OPENED        ((__force fmode_t)0x80000)
#define FMODE_CREATED       ((__force fmode_t)0x100000)

/* File is stream-like */
#define FMODE_STREAM        ((__force fmode_t)0x200000)

/* File was opened by fanotify and shouldn't generate fanotify events */
#define FMODE_NONOTIFY      ((__force fmode_t)0x4000000)

/* File is capable of returning -EAGAIN if I/O will block */
#define FMODE_NOWAIT        ((__force fmode_t)0x8000000)

/* File represents mount that needs unmounting */
#define FMODE_NEED_UNMOUNT  ((__force fmode_t)0x10000000)

/* File does not contribute to nr_files count */
#define FMODE_NOACCOUNT     ((__force fmode_t)0x20000000)

/* File supports async buffered reads */
#define FMODE_BUF_RASYNC    ((__force fmode_t)0x40000000)

/*
 * Whiteout is represented by a char device.  The following constants define the
 * mode and device number to use.
 */
#define WHITEOUT_MODE 0
#define WHITEOUT_DEV 0

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
struct file_lock;
struct iattr;
struct timespec64;
struct dir_context;
struct writeback_control;
struct readahead_control;
struct buffer_head;

/* legacy typedef, should eventually be removed */
typedef void *fl_owner_t;

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
    SB_UNFROZEN         = 0,        /* FS is unfrozen */
    SB_FREEZE_WRITE     = 1,        /* Writes, dir ops, ioctls frozen */
    SB_FREEZE_PAGEFAULT = 2,        /* Page faults stopped as well */
    SB_FREEZE_FS        = 3,        /* For internal FS use (e.g. to stop
                                     * internal threads if needed) */
    SB_FREEZE_COMPLETE  = 4,        /* ->freeze_fs finished successfully */
};

#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)

/*
 * inode->i_mutex nesting subclasses for the lock validator:
 *
 * 0: the object of the current VFS operation
 * 1: parent
 * 2: child/target
 * 3: xattr
 * 4: second non-directory
 * 5: second parent (when locking independent directories in rename)
 *
 * I_MUTEX_NONDIR2 is for certain operations (such as rename) which lock two
 * non-directories at once.
 *
 * The locking order between these classes is
 * parent[2] -> child -> grandchild -> normal -> xattr -> second non-directory
 */
enum inode_i_mutex_lock_class
{
    I_MUTEX_NORMAL,
    I_MUTEX_PARENT,
    I_MUTEX_CHILD,
    I_MUTEX_XATTR,
    I_MUTEX_NONDIR2,
    I_MUTEX_PARENT2,
};

/*
 * Write life time hint values.
 * Stored in struct inode as u8.
 */
enum rw_hint {
    WRITE_LIFE_NOT_SET  = 0,
    WRITE_LIFE_NONE     = RWH_WRITE_LIFE_NONE,
    WRITE_LIFE_SHORT    = RWH_WRITE_LIFE_SHORT,
    WRITE_LIFE_MEDIUM   = RWH_WRITE_LIFE_MEDIUM,
    WRITE_LIFE_LONG     = RWH_WRITE_LIFE_LONG,
    WRITE_LIFE_EXTREME  = RWH_WRITE_LIFE_EXTREME,
};

struct address_space_operations {
    int (*writepage)(struct page *page, struct writeback_control *wbc);
    int (*readpage)(struct file *, struct page *);

    /* Write back some dirty pages from this mapping. */
    int (*writepages)(struct address_space *, struct writeback_control *);

    /* Mark a folio dirty.  Return true if this dirtied it */
    bool (*dirty_folio)(struct address_space *, struct folio *);

    void (*readahead)(struct readahead_control *);

    int (*write_begin)(struct file *, struct address_space *mapping,
                       loff_t pos, unsigned len, unsigned flags,
                       struct page **pagep, void **fsdata);
    int (*write_end)(struct file *, struct address_space *mapping,
                     loff_t pos, unsigned len, unsigned copied,
                     struct page *page, void *fsdata);

    /* Unfortunately this kludge is needed for FIBMAP. Don't use it */
    sector_t (*bmap)(struct address_space *, sector_t);
    void (*invalidate_folio) (struct folio *, size_t offset, size_t len);
    int (*releasepage) (struct page *, gfp_t);
    void (*freepage)(struct page *);
    ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *iter);
    /*
     * migrate the contents of a page to the specified target. If
     * migrate_mode is MIGRATE_ASYNC, it must not block.
     */
    int (*migratepage)(struct address_space *,
                       struct page *, struct page *, enum migrate_mode);
    bool (*isolate_page)(struct page *, isolate_mode_t);
    void (*putback_page)(struct page *);
    int (*launder_folio)(struct folio *);
    bool (*is_partially_uptodate) (struct folio *, size_t from, size_t count);
    void (*is_dirty_writeback) (struct page *, bool *, bool *);
    int (*error_remove_page)(struct address_space *, struct page *);

    /* swapfile support */
    int (*swap_activate)(struct swap_info_struct *sis, struct file *file,
                         sector_t *span);
    void (*swap_deactivate)(struct file *file);
};

/**
 * struct address_space - Contents of a cacheable, mappable object.
 * @host: Owner, either the inode or the block_device.
 * @i_pages: Cached pages.
 * @invalidate_lock: Guards coherency between page cache contents and
 *   file offset->disk block mappings in the filesystem during invalidates.
 *   It is also used to block modification of page cache contents through
 *   memory mappings.
 * @gfp_mask: Memory allocation flags to use for allocating pages.
 * @i_mmap_writable: Number of VM_SHARED mappings.
 * @nr_thps: Number of THPs in the pagecache (non-shmem only).
 * @i_mmap: Tree of private and shared mappings.
 * @i_mmap_rwsem: Protects @i_mmap and @i_mmap_writable.
 * @nrpages: Number of page entries, protected by the i_pages lock.
 * @writeback_index: Writeback starts here.
 * @a_ops: Methods.
 * @flags: Error bits and flags (AS_*).
 * @wb_err: The most recent error which has occurred.
 * @private_lock: For use by the owner of the address_space.
 * @private_list: For use by the owner of the address_space.
 * @private_data: For use by the owner of the address_space.
 */
struct address_space {
    struct inode        *host;
    struct xarray       i_pages;
    struct rw_semaphore invalidate_lock;
    gfp_t           gfp_mask;
    atomic_t        i_mmap_writable;
    struct rb_root_cached   i_mmap;
    struct rw_semaphore i_mmap_rwsem;
    unsigned long       nrpages;
    pgoff_t         writeback_index;
    const struct address_space_operations *a_ops;
    unsigned long       flags;
    errseq_t        wb_err;
    spinlock_t      private_lock;
    struct list_head    private_list;
    void            *private_data;
} __attribute__((aligned(sizeof(long)))) __randomize_layout;

/*
 * Inode state bits.  Protected by inode->i_lock
 *
 * Four bits determine the dirty state of the inode: I_DIRTY_SYNC,
 * I_DIRTY_DATASYNC, I_DIRTY_PAGES, and I_DIRTY_TIME.
 *
 * Four bits define the lifetime of an inode.  Initially, inodes are I_NEW,
 * until that flag is cleared.  I_WILL_FREE, I_FREEING and I_CLEAR are set at
 * various stages of removing an inode.
 *
 * Two bits are used for locking and completion notification, I_NEW and I_SYNC.
 *
 * I_DIRTY_SYNC     Inode is dirty, but doesn't have to be written on
 *          fdatasync() (unless I_DIRTY_DATASYNC is also set).
 *          Timestamp updates are the usual cause.
 * I_DIRTY_DATASYNC Data-related inode changes pending.  We keep track of
 *          these changes separately from I_DIRTY_SYNC so that we
 *          don't have to write inode on fdatasync() when only
 *          e.g. the timestamps have changed.
 * I_DIRTY_PAGES    Inode has dirty pages.  Inode itself may be clean.
 * I_DIRTY_TIME     The inode itself only has dirty timestamps, and the
 *          lazytime mount option is enabled.  We keep track of this
 *          separately from I_DIRTY_SYNC in order to implement
 *          lazytime.  This gets cleared if I_DIRTY_INODE
 *          (I_DIRTY_SYNC and/or I_DIRTY_DATASYNC) gets set.  I.e.
 *          either I_DIRTY_TIME *or* I_DIRTY_INODE can be set in
 *          i_state, but not both.  I_DIRTY_PAGES may still be set.
 * I_NEW        Serves as both a mutex and completion notification.
 *          New inodes set I_NEW.  If two processes both create
 *          the same inode, one of them will release its inode and
 *          wait for I_NEW to be released before returning.
 *          Inodes in I_WILL_FREE, I_FREEING or I_CLEAR state can
 *          also cause waiting on I_NEW, without I_NEW actually
 *          being set.  find_inode() uses this to prevent returning
 *          nearly-dead inodes.
 * I_WILL_FREE      Must be set when calling write_inode_now() if i_count
 *          is zero.  I_FREEING must be set when I_WILL_FREE is
 *          cleared.
 * I_FREEING        Set when inode is about to be freed but still has dirty
 *          pages or buffers attached or the inode itself is still
 *          dirty.
 * I_CLEAR      Added by clear_inode().  In this state the inode is
 *          clean and can be destroyed.  Inode keeps I_FREEING.
 *
 *          Inodes that are I_WILL_FREE, I_FREEING or I_CLEAR are
 *          prohibited for many purposes.  iget() must wait for
 *          the inode to be completely released, then create it
 *          anew.  Other functions will just ignore such inodes,
 *          if appropriate.  I_NEW is used for waiting.
 *
 * I_SYNC       Writeback of inode is running. The bit is set during
 *          data writeback, and cleared with a wakeup on the bit
 *          address once it is done. The bit is also used to pin
 *          the inode in memory for flusher thread.
 *
 * I_REFERENCED     Marks the inode as recently references on the LRU list.
 *
 * I_DIO_WAKEUP     Never set.  Only used as a key for wait_on_bit().
 *
 * I_WB_SWITCH      Cgroup bdi_writeback switching in progress.  Used to
 *          synchronize competing switching instances and to tell
 *          wb stat updates to grab the i_pages lock.  See
 *          inode_switch_wbs_work_fn() for details.
 *
 * I_OVL_INUSE      Used by overlayfs to get exclusive ownership on upper
 *          and work dirs among overlayfs mounts.
 *
 * I_CREATING       New object's inode in the middle of setting up.
 *
 * I_DONTCACHE      Evict inode as soon as it is not used anymore.
 *
 * I_SYNC_QUEUED    Inode is queued in b_io or b_more_io writeback lists.
 *          Used to detect that mark_inode_dirty() should not move
 *          inode between dirty lists.
 *
 * I_PINNING_FSCACHE_WB Inode is pinning an fscache object for writeback.
 *
 * Q: What is the difference between I_WILL_FREE and I_FREEING?
 */
#define I_DIRTY_SYNC            (1 << 0)
#define I_DIRTY_DATASYNC        (1 << 1)
#define I_DIRTY_PAGES           (1 << 2)
#define __I_NEW                 3
#define I_NEW                   (1 << __I_NEW)
#define I_WILL_FREE             (1 << 4)
#define I_FREEING               (1 << 5)
#define I_CLEAR                 (1 << 6)
#define __I_SYNC                7
#define I_SYNC                  (1 << __I_SYNC)
#define I_REFERENCED            (1 << 8)
#define __I_DIO_WAKEUP          9
#define I_DIO_WAKEUP            (1 << __I_DIO_WAKEUP)
#define I_LINKABLE              (1 << 10)
#define I_DIRTY_TIME            (1 << 11)
#define I_WB_SWITCH             (1 << 13)
#define I_OVL_INUSE             (1 << 14)
#define I_CREATING              (1 << 15)
#define I_DONTCACHE             (1 << 16)
#define I_SYNC_QUEUED           (1 << 17)
#define I_PINNING_FSCACHE_WB    (1 << 18)

#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)

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

    const struct inode_operations   *i_op;
    struct super_block      *i_sb;
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
    spinlock_t          i_lock; /* i_blocks, i_bytes, maybe i_size */
    unsigned short      i_bytes;
    u8                  i_blkbits;
    u8                  i_write_hint;
    blkcnt_t            i_blocks;

    /* Misc */
    unsigned long       i_state;
    struct rw_semaphore i_rwsem;

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
    atomic_t        i_readcount; /* struct files open RO */
    union {
        const struct file_operations    *i_fop; /* former ->i_op->default_file_ops */
        void (*free_inode)(struct inode *);
    };
#if 0
    struct file_lock_context    *i_flctx;
#endif
    struct address_space    i_data;
    struct list_head    i_devices;
    union {
#if 0
        struct pipe_inode_info  *i_pipe;
#endif
        struct cdev     *i_cdev;
        char            *i_link;
        unsigned        i_dir_seq;
    };

    __u32 i_generation;

#if 0
    __u32           i_fsnotify_mask; /* all events this inode cares about */
    struct fsnotify_mark_connector __rcu    *i_fsnotify_marks;
#endif

    void *i_private; /* fs or device private pointer */
} __randomize_layout;

struct sb_writers {
    int frozen;         /* Is sb frozen? */
    wait_queue_head_t wait_unfrozen;  /* wait for thaw */
    struct percpu_rw_semaphore rw_sem[SB_FREEZE_LEVELS];
};

struct super_block {
    struct list_head    s_list;     /* Keep this first */
    dev_t               s_dev;      /* search index; _not_ kdev_t */
    unsigned char       s_blocksize_bits;
    unsigned long       s_blocksize;
    loff_t              s_maxbytes; /* Max file size */
    struct file_system_type *s_type;
    const struct super_operations   *s_op;
#if 0
    const struct dquot_operations   *dq_op;
    const struct quotactl_ops       *s_qcop;
#endif
    const struct export_operations  *s_export_op;
    unsigned long       s_flags;
    unsigned long       s_iflags;   /* internal SB_I_* flags */
    unsigned long       s_magic;
    struct dentry       *s_root;
    struct rw_semaphore s_umount;
    int                 s_count;
    atomic_t            s_active;
    //const struct xattr_handler **s_xattr;
    struct hlist_bl_head    s_roots;    /* alternate root dentries for NFS */
    struct list_head    s_mounts;   /* list of mounts; _not_ for fs use */
    struct block_device *s_bdev;
    struct backing_dev_info *s_bdi;
#if 0
    struct mtd_info     *s_mtd;
#endif
    struct hlist_node   s_instances;
    unsigned int        s_quota_types;  /* Bitmask of supported quota types */
#if 0
    struct quota_info   s_dquot;    /* Diskquota specific options */
#endif

    struct sb_writers   s_writers;
    /*
     * Keep s_fs_info, s_time_gran, s_fsnotify_mask, and
     * s_fsnotify_marks together for cache efficiency. They are frequently
     * accessed and rarely modified.
     */
    void                *s_fs_info; /* Filesystem private info */

    /* Granularity of c/m/atime in ns (cannot be worse than a second) */
    u32                 s_time_gran;
    /* Time limits for c/m/atime in seconds */
    time64_t            s_time_min;
    time64_t            s_time_max;
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
    const struct dentry_operations *s_d_op; /* default d_op for dentries */

    //struct shrinker s_shrink;   /* per-sb shrinker handle */

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

#if 0
    /* AIO completions deferred from interrupt context */
    struct workqueue_struct *s_dio_done_wq;
    struct hlist_head s_pins;

#endif
    /*
     * Owning user namespace and default context in which to
     * interpret filesystem uids, gids, quotas, device nodes,
     * xattrs and security labels.
     */
    struct user_namespace *s_user_ns;
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

    void (*dirty_inode)(struct inode *, int flags);
    int (*write_inode)(struct inode *, struct writeback_control *wbc);
    int (*drop_inode)(struct inode *);
    void (*evict_inode)(struct inode *);
    void (*put_super)(struct super_block *);
    int (*sync_fs)(struct super_block *sb, int wait);
    int (*freeze_super)(struct super_block *);
    int (*freeze_fs)(struct super_block *);
    int (*thaw_super)(struct super_block *);
    int (*unfreeze_fs)(struct super_block *);
    int (*statfs)(struct dentry *, struct kstatfs *);
    int (*remount_fs)(struct super_block *, int *, char *);
    void (*umount_begin)(struct super_block *);

    int (*show_options)(struct seq_file *, struct dentry *);
#if 0
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

/**
 * struct file_ra_state - Track a file's readahead state.
 * @start: Where the most recent readahead started.
 * @size: Number of pages read in the most recent readahead.
 * @async_size: Numer of pages that were/are not needed immediately
 *      and so were/are genuinely "ahead".  Start next readahead when
 *      the first of these pages is accessed.
 * @ra_pages: Maximum size of a readahead request, copied from the bdi.
 * @mmap_miss: How many mmap accesses missed in the page cache.
 * @prev_pos: The last byte in the most recent read request.
 *
 * When this structure is passed to ->readahead(), the "most recent"
 * readahead means the current readahead.
 */
struct file_ra_state {
    pgoff_t start;
    unsigned int size;
    unsigned int async_size;
    unsigned int ra_pages;
    unsigned int mmap_miss;
    loff_t prev_pos;
};

struct fown_struct {
    rwlock_t lock;          /* protects pid, uid, euid fields */
    struct pid *pid;    /* pid or -pgrp where SIGIO should be sent */
    enum pid_type pid_type; /* Kind of process group SIGIO should be sent to */
    kuid_t uid, euid;   /* uid/euid of process setting the owner */
    int signum;     /* posix.1b rt signal to be delivered on IO */
};

struct file {
    union {
        struct llist_node   fu_llist;
        struct rcu_head     fu_rcuhead;
    } f_u;
    struct path f_path;
    struct inode *f_inode;  /* cached value */
    const struct file_operations *f_op;

    /*
     * Protects f_ep, f_flags.
     * Must not be taken from IRQ context.
     */
    spinlock_t      f_lock;
    atomic_long_t   f_count;
    unsigned int    f_flags;
    fmode_t         f_mode;
    struct mutex    f_pos_lock;
    loff_t          f_pos;
    struct fown_struct  f_owner;
    const struct cred   *f_cred;
    struct file_ra_state f_ra;

    u64 f_version;

    /* needed for tty driver, and maybe others */
    void *private_data;

    /* Used by fs/eventpoll.c to link all the hooks to this file */
    struct hlist_head   *f_ep;
    struct address_space    *f_mapping;
    errseq_t        f_wb_err;
    errseq_t        f_sb_err; /* for syncfs */
} __randomize_layout __attribute__((aligned(4))); /* lest something weird
                                                     decides that 2 is OK */

struct inode_operations {
    struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
    const char * (*get_link) (struct dentry *, struct inode *, struct delayed_call *);
    int (*permission) (struct user_namespace *, struct inode *, int);
    struct posix_acl * (*get_acl)(struct inode *, int, bool);

    int (*readlink) (struct dentry *, char __user *,int);

    int (*create) (struct user_namespace *, struct inode *,struct dentry *,
               umode_t, bool);
    int (*link) (struct dentry *,struct inode *,struct dentry *);
    int (*unlink) (struct inode *,struct dentry *);
    int (*symlink) (struct user_namespace *, struct inode *,struct dentry *,
            const char *);
    int (*mkdir) (struct user_namespace *, struct inode *,struct dentry *,
              umode_t);
    int (*rmdir) (struct inode *,struct dentry *);
    int (*mknod) (struct user_namespace *, struct inode *,struct dentry *,
              umode_t,dev_t);
    int (*rename) (struct user_namespace *, struct inode *, struct dentry *,
            struct inode *, struct dentry *, unsigned int);
    int (*setattr) (struct user_namespace *, struct dentry *,
            struct iattr *);
    int (*getattr) (struct user_namespace *, const struct path *,
            struct kstat *, u32, unsigned int);
    ssize_t (*listxattr) (struct dentry *, char *, size_t);
    int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start,
              u64 len);
    int (*update_time)(struct inode *, struct timespec64 *, int);
    int (*atomic_open)(struct inode *, struct dentry *,
                       struct file *, unsigned open_flag,
                       umode_t create_mode);
    int (*tmpfile)(struct user_namespace *, struct inode *,
                   struct dentry *, umode_t);
    int (*set_acl)(struct user_namespace *, struct inode *,
                   struct posix_acl *, int);
    int (*fileattr_set)(struct user_namespace *mnt_userns,
                        struct dentry *dentry, struct fileattr *fa);
    int (*fileattr_get)(struct dentry *dentry, struct fileattr *fa);
} ____cacheline_aligned;

struct iov_iter;

struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *kiocb, struct io_comp_batch *,
            unsigned int flags);
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    __poll_t (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, loff_t, loff_t, int datasync);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **, void **);
    long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
    void (*show_fdinfo)(struct seq_file *m, struct file *f);
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
                               loff_t, size_t, unsigned int);
    loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
                               struct file *file_out, loff_t pos_out,
                               loff_t len, unsigned int remap_flags);
    int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;

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
extern int unregister_filesystem(struct file_system_type *);

extern void __init vfs_caches_init(void);

extern struct vfsmount *kern_mount(struct file_system_type *);

extern struct file_system_type *get_filesystem(struct file_system_type *fs);
extern void put_filesystem(struct file_system_type *fs);

extern void __init inode_init(void);
extern void __init inode_init_early(void);

#define MAX_NON_LFS     ((1UL<<31) - 1)

extern int inode_init_always(struct super_block *, struct inode *);

extern void iput(struct inode *);

void deactivate_super(struct super_block *sb);

/*
 * Inode flags - they have no relation to superblock flags now
 */
#define S_SYNC      (1 << 0)  /* Writes are synced at once */
#define S_NOATIME   (1 << 1)  /* Do not update access times */
#define S_APPEND    (1 << 2)  /* Append-only file */
#define S_IMMUTABLE (1 << 3)  /* Immutable file */
#define S_DEAD      (1 << 4)  /* removed, but still open directory */
#define S_NOQUOTA   (1 << 5)  /* Inode is not counted to quota */
#define S_DIRSYNC   (1 << 6)  /* Directory modifications are synchronous */
#define S_NOCMTIME  (1 << 7)  /* Do not update file c/mtime */
#define S_SWAPFILE  (1 << 8)  /* Do not truncate: swapon got its bmaps */
#define S_PRIVATE   (1 << 9)  /* Inode is fs-internal */
#define S_IMA       (1 << 10) /* Inode has an associated IMA struct */
#define S_AUTOMOUNT (1 << 11) /* Automount/referral quasi-directory */
#define S_NOSEC     (1 << 12) /* no suid or xattr security attributes */
#define S_DAX       0     /* Make all the DAX code disappear */
#define S_ENCRYPTED     (1 << 14) /* Encrypted file (using fs/crypto/) */
#define S_CASEFOLD      (1 << 15) /* Casefolded file */
#define S_VERITY        (1 << 16) /* Verity file (using fs/verity/) */
#define S_KERNEL_FILE   (1 << 17) /* File is in use by the kernel (eg. fs/cachefiles) */

static inline bool sb_rdonly(const struct super_block *sb)
{
    return sb->s_flags & SB_RDONLY;
}

/*
 * Note that nosuid etc flags are inode-specific: setting some file-system
 * flags just means all the inodes inherit those flags by default. It might be
 * possible to override it selectively if you really wanted to with some
 * ioctl() that is not currently implemented.
 *
 * Exception: SB_RDONLY is always applied to the entire file system.
 *
 * Unfortunately, it is possible to change a filesystems flags with it mounted
 * with files in use.  This means that all of the inodes will not have their
 * i_flags updated.  Hence, i_flags no longer inherit the superblock mount
 * flags, so these have to be checked separately. -- rmk@arm.uk.linux.org
 */
#define __IS_FLG(inode, flg)    ((inode)->i_sb->s_flags & (flg))

#define IS_RDONLY(inode)    sb_rdonly((inode)->i_sb)
#define IS_SYNC(inode)      (__IS_FLG(inode, SB_SYNCHRONOUS) || \
                             ((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode)   (__IS_FLG(inode, SB_SYNCHRONOUS|SB_DIRSYNC) || \
                             ((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_MANDLOCK(inode)  __IS_FLG(inode, SB_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, SB_RDONLY|SB_NOATIME)
#define IS_I_VERSION(inode) __IS_FLG(inode, SB_I_VERSION)

#define IS_NOQUOTA(inode)   ((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode)    ((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode) ((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode)  __IS_FLG(inode, SB_POSIXACL)

#define IS_DEADDIR(inode)   ((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode)  ((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode)  ((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode)   ((inode)->i_flags & S_PRIVATE)
#define IS_IMA(inode)       ((inode)->i_flags & S_IMA)
#define IS_AUTOMOUNT(inode) ((inode)->i_flags & S_AUTOMOUNT)
#define IS_NOSEC(inode)     ((inode)->i_flags & S_NOSEC)
#define IS_DAX(inode)       ((inode)->i_flags & S_DAX)
#define IS_ENCRYPTED(inode) ((inode)->i_flags & S_ENCRYPTED)
#define IS_CASEFOLDED(inode)    ((inode)->i_flags & S_CASEFOLD)
#define IS_VERITY(inode)    ((inode)->i_flags & S_VERITY)

#define IS_WHITEOUT(inode)  (S_ISCHR(inode->i_mode) && \
                 (inode)->i_rdev == WHITEOUT_DEV)

#define MAY_EXEC        0x00000001
#define MAY_WRITE       0x00000002
#define MAY_READ        0x00000004
#define MAY_APPEND      0x00000008
#define MAY_ACCESS      0x00000010
#define MAY_OPEN        0x00000020
#define MAY_CHDIR       0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK   0x00000080

static inline int inode_unhashed(struct inode *inode)
{
    return hlist_unhashed(&inode->i_hash);
}

void kill_block_super(struct super_block *sb);
void kill_anon_super(struct super_block *sb);
void kill_litter_super(struct super_block *sb);

extern int generic_delete_inode(struct inode *inode);

/*
 * Userspace may rely on the the inode number being non-zero. For example, glibc
 * simply ignores files with zero i_ino in unlink() and other places.
 *
 * As an additional complication, if userspace was compiled with
 * _FILE_OFFSET_BITS=32 on a 64-bit kernel we'll only end up reading out the
 * lower 32 bits, so we need to check that those aren't zero explicitly. With
 * _FILE_OFFSET_BITS=64, this may cause some harmless false-negatives, but
 * better safe than sorry.
 */
static inline bool is_zero_ino(ino_t ino)
{
    return (u32)ino == 0;
}

extern void inc_nlink(struct inode *inode);

extern const struct file_operations simple_dir_operations;
extern const struct inode_operations simple_dir_inode_operations;

extern struct dentry *
simple_lookup(struct inode *, struct dentry *, unsigned int flags);

extern void __init vfs_caches_init_early(void);

/* fs/open.c */
struct audit_names;
struct filename {
    const char          *name;  /* pointer to actual string */
    const __user char   *uptr;  /* original userland pointer */
    int                 refcnt;
    struct audit_names  *aname;
    const char          iname[];
};
static_assert(offsetof(struct filename, iname) % sizeof(long) == 0);

/* When fs/namei.c:getname() is called, we store the pointer in name and bump
 * the refcnt in the associated filename struct.
 *
 * Further, in fs/namei.c:path_lookup() we store the inode and device.
 */
struct audit_names {
    struct list_head    list;       /* audit_context->names_list */

#if 0
    struct filename     *name;
    int                 name_len;   /* number of chars to log */
    bool                hidden;     /* don't log this record */

    unsigned long       ino;
    dev_t           dev;
    umode_t         mode;
    kuid_t          uid;
    kgid_t          gid;
    dev_t           rdev;
    u32         osid;
    struct audit_cap_data   fcap;
    unsigned int        fcap_ver;
    unsigned char       type;       /* record type */
    /*
     * This was an allocated audit_names and not from the array of
     * names allocated in the task audit context.  Thus this name
     * should be freed on syscall exit.
     */
    bool            should_free;
#endif
};

extern struct kmem_cache *names_cachep;

#define __getname()         kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name)     kmem_cache_free(names_cachep, (void *)(name))

/* fs/dcache.c -- generic fs support functions */
extern bool is_subdir(struct dentry *, struct dentry *);
extern bool path_is_under(const struct path *, const struct path *);

static inline void inode_lock(struct inode *inode)
{
    down_write(&inode->i_rwsem);
}

static inline void inode_unlock(struct inode *inode)
{
    up_write(&inode->i_rwsem);
}

static inline void inode_lock_nested(struct inode *inode, unsigned subclass)
{
    down_write_nested(&inode->i_rwsem, subclass);
}

extern int current_umask(void);

/*
 * VFS helper functions..
 */
int vfs_create(struct user_namespace *, struct inode *,
               struct dentry *, umode_t, bool);
int vfs_mkdir(struct user_namespace *, struct inode *,
              struct dentry *, umode_t);
int vfs_mknod(struct user_namespace *, struct inode *, struct dentry *,
              umode_t, dev_t);
int vfs_symlink(struct user_namespace *, struct inode *,
                struct dentry *, const char *);
int vfs_link(struct dentry *, struct user_namespace *, struct inode *,
             struct dentry *, struct inode **);
int vfs_rmdir(struct user_namespace *, struct inode *, struct dentry *);
int vfs_unlink(struct user_namespace *, struct inode *, struct dentry *,
               struct inode **);

/*
 * These are internal functions, please use sb_start_{write,pagefault,intwrite}
 * instead.
 */
static inline void __sb_end_write(struct super_block *sb, int level)
{
    percpu_up_read(sb->s_writers.rw_sem + level-1);
}

/**
 * sb_end_write - drop write access to a superblock
 * @sb: the super we wrote to
 *
 * Decrement number of writers to the filesystem. Wake up possible waiters
 * wanting to freeze the filesystem.
 */
static inline void sb_end_write(struct super_block *sb)
{
    __sb_end_write(sb, SB_FREEZE_WRITE);
}

/*
 * VFS file helper functions.
 */
void inode_init_owner(struct user_namespace *mnt_userns, struct inode *inode,
                      const struct inode *dir, umode_t mode);
extern bool may_open_dev(const struct path *path);

extern const struct file_operations def_blk_fops;
extern const struct file_operations def_chr_fops;

extern loff_t noop_llseek(struct file *file, loff_t offset, int whence);
extern loff_t no_llseek(struct file *file, loff_t offset, int whence);

extern void init_special_inode(struct inode *, umode_t, dev_t);

extern unsigned int get_next_ino(void);

extern const struct address_space_operations ram_aops;

extern void ihold(struct inode * inode);

extern int simple_statfs(struct dentry *, struct kstatfs *);
extern int simple_open(struct inode *inode, struct file *file);
extern int simple_link(struct dentry *, struct inode *, struct dentry *);
extern int simple_unlink(struct inode *, struct dentry *);
extern int simple_rmdir(struct inode *, struct dentry *);
extern int simple_rename_exchange(struct inode *old_dir,
                                  struct dentry *old_dentry,
                                  struct inode *new_dir,
                                  struct dentry *new_dentry);
extern int simple_rename(struct user_namespace *, struct inode *,
                         struct dentry *, struct inode *, struct dentry *,
                         unsigned int);

int inode_permission(struct user_namespace *, struct inode *, int);

static inline int path_permission(const struct path *path, int mask)
{
    return inode_permission(mnt_user_ns(path->mnt),
                            d_inode(path->dentry), mask);
}

static inline void inode_lock_shared(struct inode *inode)
{
    down_read(&inode->i_rwsem);
}

static inline void inode_unlock_shared(struct inode *inode)
{
    up_read(&inode->i_rwsem);
}

extern int generic_file_mmap(struct file *, struct vm_area_struct *);

/* fs/splice.c */
extern ssize_t
generic_file_splice_read(struct file *, loff_t *,
                         struct pipe_inode_info *, size_t, unsigned int);
extern ssize_t
iter_file_splice_write(struct pipe_inode_info *,
                       struct file *, loff_t *, size_t, unsigned int);
extern ssize_t
generic_splice_sendpage(struct pipe_inode_info *pipe, struct file *out,
                        loff_t *, size_t len, unsigned int flags);
extern long
do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
                 loff_t *opos, size_t len, unsigned int flags);

int __init list_bdev_fs_names(char *buf, size_t size);

extern struct file_system_type *get_fs_type(const char *name);
extern struct super_block *get_super(struct block_device *);
extern struct super_block *get_active_super(struct block_device *bdev);
extern void drop_super(struct super_block *sb);
extern void drop_super_exclusive(struct super_block *sb);
extern void iterate_supers(void (*)(struct super_block *, void *), void *);
extern void iterate_supers_type(struct file_system_type *,
                                void (*)(struct super_block *, void *), void *);

extern struct dentry *
mount_bdev(struct file_system_type *fs_type,
           int flags, const char *dev_name, void *data,
           int (*fill_super)(struct super_block *, void *, int));

extern struct inode *
ilookup5_nowait(struct super_block *sb, unsigned long hashval,
                int (*test)(struct inode *, void *), void *data);

extern struct inode *
ilookup5(struct super_block *sb, unsigned long hashval,
         int (*test)(struct inode *, void *), void *data);

extern struct inode *ilookup(struct super_block *sb, unsigned long ino);

extern void __insert_inode_hash(struct inode *, unsigned long hashval);
static inline void insert_inode_hash(struct inode *inode)
{
    __insert_inode_hash(inode, inode->i_ino);
}

/*
 * NOTE: in a 32bit arch with a preemptable kernel and
 * an UP compile the i_size_read/write must be atomic
 * with respect to the local cpu (unlike with preempt disabled),
 * but they don't need to be atomic with respect to other cpus like in
 * true SMP (so they need either to either locally disable irq around
 * the read or for example on x86 they can be still implemented as a
 * cmpxchg8b without the need of the lock prefix). For SMP compiles
 * and 64bit archs it makes no difference if preempt is enabled or not.
 */
static inline loff_t i_size_read(const struct inode *inode)
{
    return inode->i_size;
}

/*
 * NOTE: unlike i_size_read(), i_size_write() does need locking around it
 * (normally i_mutex), otherwise on 32bit/SMP an update of i_size_seqcount
 * can be lost, resulting in subsequent i_size_read() calls spinning forever.
 */
static inline void i_size_write(struct inode *inode, loff_t i_size)
{
    inode->i_size = i_size;
}

extern void __remove_inode_hash(struct inode *);
static inline void remove_inode_hash(struct inode *inode)
{
    if (!inode_unhashed(inode) && !hlist_fake(&inode->i_hash))
        __remove_inode_hash(inode);
}

typedef int (get_block_t)(struct inode *inode, sector_t iblock,
                          struct buffer_head *bh_result, int create);

extern int buffer_migrate_page(struct address_space *,
                               struct page *, struct page *,
                               enum migrate_mode);
extern int buffer_migrate_page_norefs(struct address_space *,
                                      struct page *, struct page *,
                                      enum migrate_mode);

extern int sb_set_blocksize(struct super_block *, int);

extern int sb_min_blocksize(struct super_block *, int);

/*
 * Returns true if any of the pages in the mapping are marked with the tag.
 */
static inline bool mapping_tagged(struct address_space *mapping, xa_mark_t tag)
{
    return xa_marked(&mapping->i_pages, tag);
}

extern struct super_block *blockdev_superblock;
static inline bool sb_is_blkdev_sb(struct super_block *sb)
{
    return sb == blockdev_superblock;
}

extern void inode_sb_list_add(struct inode *inode);
extern void inode_add_lru(struct inode *inode);

extern struct inode *iget_locked(struct super_block *, unsigned long);

extern void unlock_new_inode(struct inode *);

extern void iget_failed(struct inode *);

/**
 * i_uid_into_mnt - map an inode's i_uid down into a mnt_userns
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode: inode to map
 *
 * Return: the inode's i_uid mapped down according to @mnt_userns.
 * If the inode's i_uid has no mapping INVALID_UID is returned.
 */
static inline
struct user_namespace *i_user_ns(const struct inode *inode)
{
    return inode->i_sb->s_user_ns;
}

/* Helper functions so that in most cases filesystems will
 * not need to deal directly with kuid_t and kgid_t and can
 * instead deal with the raw numeric values that are stored
 * in the filesystem.
 */
static inline uid_t i_uid_read(const struct inode *inode)
{
    //return from_kuid(i_user_ns(inode), inode->i_uid);
    panic("%s: END!\n", __func__);
}

static inline gid_t i_gid_read(const struct inode *inode)
{
    //return from_kgid(i_user_ns(inode), inode->i_gid);
    panic("%s: END!\n", __func__);
}

static inline void i_uid_write(struct inode *inode, uid_t uid)
{
    //inode->i_uid = make_kuid(i_user_ns(inode), uid);
    panic("%s: END!\n", __func__);
}

static inline void i_gid_write(struct inode *inode, gid_t gid)
{
    //inode->i_gid = make_kgid(i_user_ns(inode), gid);
    panic("%s: END!\n", __func__);
}

extern int generic_file_open(struct inode *inode, struct file *filp);

extern ssize_t generic_read_dir(struct file *, char __user *, size_t, loff_t *);

extern loff_t generic_file_llseek(struct file *file, loff_t offset, int whence);

void deactivate_locked_super(struct super_block *sb);

static inline void i_mmap_lock_write(struct address_space *mapping)
{
    down_write(&mapping->i_mmap_rwsem);
}

static inline int i_mmap_trylock_write(struct address_space *mapping)
{
    return down_write_trylock(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_write(struct address_space *mapping)
{
    up_write(&mapping->i_mmap_rwsem);
}

static inline bool vma_is_fsdax(struct vm_area_struct *vma)
{
    return false;
}

#define __FMODE_EXEC        ((__force int) FMODE_EXEC)
#define __FMODE_NONOTIFY    ((__force int) FMODE_NONOTIFY)

#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define OPEN_FMODE(flag) \
    ((__force fmode_t)(((flag + 1) & O_ACCMODE) | (flag & __FMODE_NONOTIFY)))

extern void __init files_init(void);
extern void __init files_maxfiles_init(void);

static inline unsigned int i_blocksize(const struct inode *node)
{
    return (1 << node->i_blkbits);
}

extern ssize_t generic_file_read_iter(struct kiocb *, struct iov_iter *);
extern ssize_t __generic_file_write_iter(struct kiocb *, struct iov_iter *);
extern ssize_t generic_file_write_iter(struct kiocb *, struct iov_iter *);

extern bool path_noexec(const struct path *path);
extern void inode_nohighmem(struct inode *inode);

#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

/* Alas, no aliases. Too much hassle with bringing module.h everywhere */
#define fops_get(fops) \
    (((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
    do { if (fops) module_put((fops)->owner); } while(0)

static inline void i_readcount_dec(struct inode *inode)
{
    BUG_ON(!atomic_read(&inode->i_readcount));
    atomic_dec(&inode->i_readcount);
}
static inline void i_readcount_inc(struct inode *inode)
{
    atomic_inc(&inode->i_readcount);
}

extern void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping);

extern loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize);
extern loff_t generic_file_llseek_size(struct file *file, loff_t offset,
        int whence, loff_t maxsize, loff_t eof);
extern loff_t fixed_size_llseek(struct file *file, loff_t offset,
        int whence, loff_t size);
extern loff_t no_seek_end_llseek_size(struct file *, loff_t, int, loff_t);
extern loff_t no_seek_end_llseek(struct file *, loff_t, int);
int rw_verify_area(int, struct file *, const loff_t *, size_t);
extern int nonseekable_open(struct inode * inode, struct file * filp);
extern int stream_open(struct inode * inode, struct file * filp);

static inline struct inode *file_inode(const struct file *f)
{
    return f->f_inode;
}

/*
 * This is used for regular files where some users -- especially the
 * currently executed binary in a process, previously handled via
 * VM_DENYWRITE -- cannot handle concurrent write (and maybe mmap
 * read-write shared) accesses.
 *
 * get_write_access() gets write permission for a file.
 * put_write_access() releases this write permission.
 * deny_write_access() denies write access to a file.
 * allow_write_access() re-enables write access to a file.
 *
 * The i_writecount field of an inode can have the following values:
 * 0: no write access, no denied write access
 * < 0: (-i_writecount) users that denied write access to the file.
 * > 0: (i_writecount) users that have write access to the file.
 *
 * Normally we operate on that counter with atomic_{inc,dec} and it's safe
 * except for the cases where we don't hold i_writecount yet. Then we need to
 * use {get,deny}_write_access() - these functions check the sign and refuse
 * to do the change if sign is wrong.
 */
static inline int get_write_access(struct inode *inode)
{
    return atomic_inc_unless_negative(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline int deny_write_access(struct file *file)
{
    struct inode *inode = file_inode(file);
    return atomic_dec_unless_positive(&inode->i_writecount) ? 0 : -ETXTBSY;
}
static inline void put_write_access(struct inode * inode)
{
    atomic_dec(&inode->i_writecount);
}
static inline void allow_write_access(struct file *file)
{
    if (file)
        atomic_inc(&file_inode(file)->i_writecount);
}
static inline bool inode_is_open_for_write(const struct inode *inode)
{
    return atomic_read(&inode->i_writecount) > 0;
}

extern ssize_t kernel_read(struct file *, void *, size_t, loff_t *);
ssize_t __kernel_read(struct file *file, void *buf, size_t count, loff_t *pos);
extern ssize_t kernel_write(struct file *, const void *, size_t, loff_t *);
extern ssize_t __kernel_write(struct file *, const void *, size_t, loff_t *);
extern struct file *open_exec(const char *);

#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)

/* Match RWF_* bits to IOCB bits */
#define IOCB_HIPRI      (__force int) RWF_HIPRI
#define IOCB_DSYNC      (__force int) RWF_DSYNC
#define IOCB_SYNC       (__force int) RWF_SYNC
#define IOCB_NOWAIT     (__force int) RWF_NOWAIT
#define IOCB_APPEND     (__force int) RWF_APPEND

/* non-RWF related bits - start at 16 */
#define IOCB_EVENTFD        (1 << 16)
#define IOCB_DIRECT         (1 << 17)
#define IOCB_WRITE          (1 << 18)
/* iocb->ki_waitq is valid */
#define IOCB_WAITQ          (1 << 19)
#define IOCB_NOIO           (1 << 20)
/* can use bio alloc cache */
#define IOCB_ALLOC_CACHE    (1 << 21)

struct kiocb {
    struct file     *ki_filp;

    /* The 'ki_filp' pointer is shared in a union for aio */

    loff_t          ki_pos;
    void (*ki_complete)(struct kiocb *iocb, long ret);
    void            *private;
    int             ki_flags;
    u16             ki_ioprio; /* See linux/ioprio.h */
    struct wait_page_queue  *ki_waitq; /* for async buffered IO */
};

static inline int iocb_flags(struct file *file)
{
    int res = 0;
    if (file->f_flags & O_APPEND)
        res |= IOCB_APPEND;
    if (file->f_flags & O_DIRECT)
        res |= IOCB_DIRECT;
    if ((file->f_flags & O_DSYNC) || IS_SYNC(file->f_mapping->host))
        res |= IOCB_DSYNC;
    if (file->f_flags & __O_SYNC)
        res |= IOCB_SYNC;
    return res;
}

static inline void init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
    *kiocb = (struct kiocb) {
        .ki_filp = filp,
        .ki_flags = iocb_flags(filp),
        .ki_ioprio = get_current_ioprio(),
    };
}

static inline void filemap_invalidate_lock_shared(struct address_space *mapping)
{
    down_read(&mapping->invalidate_lock);
}

static inline void filemap_invalidate_unlock_shared(
                    struct address_space *mapping)
{
    up_read(&mapping->invalidate_lock);
}

static inline int
filemap_invalidate_trylock_shared(struct address_space *mapping)
{
    return down_read_trylock(&mapping->invalidate_lock);
}

/*
 * Might pages of this file have been modified in userspace?
 * Note that i_mmap_writable counts all VM_SHARED vmas: do_mmap
 * marks vma as VM_SHARED if it is shared, and the file was opened for
 * writing i.e. vma may be mprotected writable even if now readonly.
 *
 * If i_mmap_writable is negative, no new writable mappings are allowed. You
 * can only deny writable mappings, if none exists right now.
 */
static inline int mapping_writably_mapped(struct address_space *mapping)
{
    return atomic_read(&mapping->i_mmap_writable) > 0;
}

static inline void file_accessed(struct file *file)
{
#if 0
    if (!(file->f_flags & O_NOATIME))
        touch_atime(&file->f_path);
#endif
}

static inline struct file *get_file(struct file *f)
{
    atomic_long_inc(&f->f_count);
    return f;
}

#define file_count(x)   atomic_long_read(&(x)->f_count)

extern struct file *file_open_name(struct filename *, int, umode_t);
extern struct file *filp_open(const char *, int, umode_t);
extern struct file *file_open_root(const struct path *,
                                   const char *, int, umode_t);

extern int filp_close(struct file *, fl_owner_t id);

static inline int mapping_map_writable(struct address_space *mapping)
{
    return atomic_inc_unless_negative(&mapping->i_mmap_writable) ?
        0 : -EPERM;
}

static inline void mapping_unmap_writable(struct address_space *mapping)
{
    atomic_dec(&mapping->i_mmap_writable);
}

static inline int mapping_deny_writable(struct address_space *mapping)
{
    return atomic_dec_unless_positive(&mapping->i_mmap_writable) ?
        0 : -EBUSY;
}

static inline void mapping_allow_writable(struct address_space *mapping)
{
    atomic_inc(&mapping->i_mmap_writable);
}

static inline bool vma_is_dax(const struct vm_area_struct *vma)
{
    return vma->vm_file && IS_DAX(vma->vm_file->f_mapping->host);
}

static inline
int call_mmap(struct file *file, struct vm_area_struct *vma)
{
    return file->f_op->mmap(file, vma);
}

extern void __mark_inode_dirty(struct inode *, int);

static inline void mark_inode_dirty_sync(struct inode *inode)
{
    __mark_inode_dirty(inode, I_DIRTY_SYNC);
}

static inline int generic_drop_inode(struct inode *inode)
{
    return !inode->i_nlink || inode_unhashed(inode);
}

/*
 * This is the "filldir" function type, used by readdir() to let
 * the kernel specify what kind of dirent layout it wants to have.
 * This allows the kernel to read directories into kernel space or
 * to have different dirent layouts depending on the binary type.
 */
struct dir_context;
typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64,
                         unsigned);

struct dir_context {
    filldir_t actor;
    loff_t pos;
};

extern int always_delete_dentry(const struct dentry *);

static inline void i_mmap_lock_read(struct address_space *mapping)
{
    down_read(&mapping->i_mmap_rwsem);
}

static inline void i_mmap_unlock_read(struct address_space *mapping)
{
    up_read(&mapping->i_mmap_rwsem);
}

extern struct filename *getname_flags(const char __user *, int, int *);
extern struct filename *getname_uflags(const char __user *, int);
extern struct filename *getname(const char __user *);
extern struct filename *getname_kernel(const char *);
extern void putname(struct filename *name);

static inline
ssize_t call_read_iter(struct file *file, struct kiocb *kio,
                       struct iov_iter *iter)
{
    return file->f_op->read_iter(kio, iter);
}

int vfs_fstatat(int dfd, const char __user *filename,
                struct kstat *stat, int flags);
int vfs_fstat(int fd, struct kstat *stat);

static inline
int vfs_stat(const char __user *filename, struct kstat *stat)
{
    printk("--------- %s: ...\n", __func__);
    return vfs_fstatat(AT_FDCWD, filename, stat, 0);
}

static inline
kuid_t i_uid_into_mnt(struct user_namespace *mnt_userns,
                      const struct inode *inode)
{
    return mapped_kuid_fs(mnt_userns, i_user_ns(inode), inode->i_uid);
}

/**
 * i_gid_into_mnt - map an inode's i_gid down into a mnt_userns
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode: inode to map
 *
 * Return: the inode's i_gid mapped down according to @mnt_userns.
 * If the inode's i_gid has no mapping INVALID_GID is returned.
 */
static inline
kgid_t i_gid_into_mnt(struct user_namespace *mnt_userns,
                      const struct inode *inode)
{
    return mapped_kgid_fs(mnt_userns, i_user_ns(inode), inode->i_gid);
}

void generic_fillattr(struct user_namespace *, struct inode *,
                      struct kstat *);

extern struct timespec64 current_time(struct inode *inode);

struct timespec64 timestamp_truncate(struct timespec64 t,
                                     struct inode *inode);

extern void locks_remove_posix(struct file *, fl_owner_t);

#define locks_inode(f) file_inode(f)

#define get_file_rcu_many(x, cnt)   \
    atomic_long_add_unless(&(x)->f_count, (cnt), 0)

static inline
bool HAS_UNMAPPED_ID(struct user_namespace *mnt_userns,
                     struct inode *inode)
{
    return !uid_valid(i_uid_into_mnt(mnt_userns, inode)) ||
           !gid_valid(i_gid_into_mnt(mnt_userns, inode));
}

/* fs/char_dev.c */
#define CHRDEV_MAJOR_MAX 512
/* Marks the bottom of the first segment of free char majors */
#define CHRDEV_MAJOR_DYN_END 234
/* Marks the top and bottom of the second segment of free char majors */
#define CHRDEV_MAJOR_DYN_EXT_START 511
#define CHRDEV_MAJOR_DYN_EXT_END 384

extern int alloc_chrdev_region(dev_t *, unsigned, unsigned,
                               const char *);
extern int register_chrdev_region(dev_t, unsigned, const char *);
extern int __register_chrdev(unsigned int major,
                             unsigned int baseminor,
                             unsigned int count,
                             const char *name,
                             const struct file_operations *fops);
extern void __unregister_chrdev(unsigned int major,
                                unsigned int baseminor,
                                unsigned int count,
                                const char *name);
extern void unregister_chrdev_region(dev_t, unsigned);
extern void chrdev_show(struct seq_file *,off_t);

static inline
int register_chrdev(unsigned int major, const char *name,
                    const struct file_operations *fops)
{
    return __register_chrdev(major, 0, 256, name, fops);
}

/*
 * This one is to be used *ONLY* from ->open() instances.
 * fops must be non-NULL, pinned down *and* module dependencies
 * should be sufficient to pin the caller down as well.
 */
#define replace_fops(f, fops) \
    do {    \
        struct file *__file = (f); \
        fops_put(__file->f_op); \
        BUG_ON(!(__file->f_op = (fops))); \
    } while(0)

extern int nonseekable_open(struct inode * inode, struct file * filp);

static inline void __sb_start_write(struct super_block *sb, int level)
{
    percpu_down_read(sb->s_writers.rw_sem + level - 1);
}

/**
 * sb_start_write - get write access to a superblock
 * @sb: the super we write to
 *
 * When a process wants to write data or metadata to a file system (i.e. dirty
 * a page or an inode), it should embed the operation in a sb_start_write() -
 * sb_end_write() pair to get exclusion against file system freezing. This
 * function increments number of writers preventing freezing. If the file
 * system is already frozen, the function waits until the file system is
 * thawed.
 *
 * Since freeze protection behaves as a lock, users have to preserve
 * ordering of freeze protection and other filesystem locks. Generally,
 * freeze protection should be the outermost lock. In particular, we have:
 *
 * sb_start_write
 *   -> i_mutex         (write path, truncate, directory ops, ...)
 *   -> s_umount        (freeze_super, thaw_super)
 */
static inline void sb_start_write(struct super_block *sb)
{
    __sb_start_write(sb, SB_FREEZE_WRITE);
}

static inline void file_start_write(struct file *file)
{
    if (!S_ISREG(file_inode(file)->i_mode))
        return;
    sb_start_write(file_inode(file)->i_sb);
}

static inline
ssize_t call_write_iter(struct file *file, struct kiocb *kio,
                        struct iov_iter *iter)
{
    return file->f_op->write_iter(kio, iter);
}

static inline void file_end_write(struct file *file)
{
    if (!S_ISREG(file_inode(file)->i_mode))
        return;
    __sb_end_write(file_inode(file)->i_sb, SB_FREEZE_WRITE);
}

#endif /* _LINUX_FS_H */
