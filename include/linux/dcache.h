/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_DCACHE_H
#define __LINUX_DCACHE_H

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/math.h>
#include <linux/rculist.h>
#include <linux/rculist_bl.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/lockref.h>
#include <linux/stringhash.h>
#include <linux/wait.h>

#define IS_ROOT(x) ((x) == (x)->d_parent)

#define DNAME_INLINE_LEN    32  /* 192 bytes */

#define DCACHE_MOUNTED          0x00010000 /* is a mountpoint */
#define DCACHE_NEED_AUTOMOUNT   0x00020000 /* handle automount on this dir */
#define DCACHE_MANAGE_TRANSIT   0x00040000 /* manage transit from this dirent */
#define DCACHE_MANAGED_DENTRY \
    (DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)

#define DCACHE_LRU_LIST         0x00080000

#define DCACHE_ENTRY_TYPE       0x00700000
#define DCACHE_MISS_TYPE        0x00000000 /* Negative dentry (maybe fallthru to nowhere) */
#define DCACHE_WHITEOUT_TYPE    0x00100000 /* Whiteout dentry (stop pathwalk) */
#define DCACHE_DIRECTORY_TYPE   0x00200000 /* Normal directory */
#define DCACHE_AUTODIR_TYPE     0x00300000 /* Lookupless directory (presumed automount) */
#define DCACHE_REGULAR_TYPE     0x00400000 /* Regular file type (or fallthru to such) */
#define DCACHE_SPECIAL_TYPE     0x00500000 /* Other file type (or fallthru to such) */
#define DCACHE_SYMLINK_TYPE     0x00600000 /* Symlink (or fallthru to such) */

#define DCACHE_MAY_FREE         0x00800000
#define DCACHE_FALLTHRU         0x01000000 /* Fall through to lower layer */
#define DCACHE_NOKEY_NAME       0x02000000 /* Encrypted name encoded without key */
#define DCACHE_OP_REAL          0x04000000

#define DCACHE_PAR_LOOKUP       0x10000000 /* being looked up (with parent locked shared) */
#define DCACHE_DENTRY_CURSOR    0x20000000
#define DCACHE_NORCU            0x40000000 /* No RCU delay for freeing */

struct path;
struct vfsmount;

#define HASH_LEN_DECLARE u32 hash; u32 len
#define bytemask_from_count(cnt)   (~(~0ul << (cnt)*8))

/*
 * "quick string" -- eases parameter passing, but more importantly
 * saves "metadata" about the string (ie length and the hash).
 *
 * hash comes first so it snuggles against d_parent in the
 * dentry.
 */
struct qstr {
    union {
        struct {
            HASH_LEN_DECLARE;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }

#define d_lock  d_lockref.lock

struct dentry {
    /* RCU lookup touched fields */
    unsigned int d_flags;       /* protected by d_lock */
    seqcount_spinlock_t d_seq;  /* per dentry seqlock */
    struct hlist_bl_node d_hash;    /* lookup hash list */
    struct dentry *d_parent;    /* parent directory */
    struct qstr d_name;
    struct inode *d_inode;      /* Where the name belongs to - NULL is
                                   negative */
    unsigned char d_iname[DNAME_INLINE_LEN];    /* small names */

    /* Ref lookup also touches following */
    struct lockref d_lockref;   /* per-dentry lock and refcount */
    const struct dentry_operations *d_op;
    struct super_block *d_sb;   /* The root of the dentry tree */
    unsigned long d_time;       /* used by d_revalidate */
    void *d_fsdata;         /* fs-specific data */

    union {
        struct list_head d_lru;     /* LRU list */
        wait_queue_head_t *d_wait;  /* in-lookup ones only */
    };
    struct list_head d_child;   /* child of parent list */
    struct list_head d_subdirs; /* our children */
    /*
     * d_alias and d_rcu can share memory
     */
    union {
        struct hlist_node d_alias;  /* inode alias list */
        struct hlist_bl_node d_in_lookup_hash;  /* only for in-lookup ones */
        struct rcu_head d_rcu;
    } d_u;
} __randomize_layout;

struct dentry_operations {
    int (*d_revalidate)(struct dentry *, unsigned int);
    int (*d_weak_revalidate)(struct dentry *, unsigned int);
    int (*d_hash)(const struct dentry *, struct qstr *);
    int (*d_compare)(const struct dentry *,
            unsigned int, const char *, const struct qstr *);
    int (*d_delete)(const struct dentry *);
    int (*d_init)(struct dentry *);
    void (*d_release)(struct dentry *);
    void (*d_prune)(struct dentry *);
    void (*d_iput)(struct dentry *, struct inode *);
    char *(*d_dname)(struct dentry *, char *, int);
    struct vfsmount *(*d_automount)(struct path *);
    int (*d_manage)(const struct path *, bool);
    struct dentry *(*d_real)(struct dentry *, const struct inode *);
} ____cacheline_aligned;

/*
 * dentry->d_lock spinlock nesting subclasses:
 *
 * 0: normal
 * 1: nested
 */
enum dentry_d_lock_class
{
    DENTRY_D_LOCK_NORMAL, /* implicitly used by plain spin_lock() APIs. */
    DENTRY_D_LOCK_NESTED
};

static inline struct dentry *dget(struct dentry *dentry)
{
    if (dentry)
        lockref_get(&dentry->d_lockref);
    return dentry;
}

/* only used at mount-time */
extern struct dentry *d_make_root(struct inode *);

static inline int d_in_lookup(const struct dentry *dentry)
{
    return dentry->d_flags & DCACHE_PAR_LOOKUP;
}

extern void dput(struct dentry *);

/**
 *  d_unhashed -    is dentry hashed
 *  @dentry: entry to check
 *
 *  Returns true if the dentry passed is not currently hashed.
 */

static inline int d_unhashed(const struct dentry *dentry)
{
    return hlist_bl_unhashed(&dentry->d_hash);
}

/*
 * Locking rules for dentry_operations callbacks are to be found in
 * Documentation/filesystems/locking.rst. Keep it updated!
 *
 * FUrther descriptions are found in Documentation/filesystems/vfs.rst.
 * Keep it updated too!
 */

/* d_flags entries */
#define DCACHE_OP_HASH          0x00000001
#define DCACHE_OP_COMPARE       0x00000002
#define DCACHE_OP_REVALIDATE    0x00000004
#define DCACHE_OP_DELETE        0x00000008
#define DCACHE_OP_PRUNE         0x00000010

#define DCACHE_DISCONNECTED     0x00000020
     /* This dentry is possibly not currently connected to the dcache tree, in
      * which case its parent will either be itself, or will have this flag as
      * well.  nfsd will not use a dentry with this bit set, but will first
      * endeavour to clear the bit either by discovering that it is connected,
      * or by performing lookup operations.   Any filesystem which supports
      * nfsd_operations MUST have a lookup function which, if it finds a
      * directory inode with a DCACHE_DISCONNECTED dentry, will d_move that
      * dentry into place and return that dentry rather than the passed one,
      * typically using d_splice_alias. */

#define DCACHE_REFERENCED       0x00000040 /* Recently used, don't discard. */

#define DCACHE_DONTCACHE        0x00000080 /* Purge from memory on final dput() */

#define DCACHE_CANT_MOUNT       0x00000100
#define DCACHE_GENOCIDE         0x00000200
#define DCACHE_SHRINK_LIST      0x00000400

#define DCACHE_OP_WEAK_REVALIDATE   0x00000800

/* allocate/de-allocate */
extern struct dentry *d_alloc(struct dentry *, const struct qstr *);

/* appendix may either be NULL or be used for transname suffixes */
extern struct dentry *d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *d_hash_and_lookup(struct dentry *, struct qstr *);
extern struct dentry *__d_lookup(const struct dentry *, const struct qstr *);
extern struct dentry *__d_lookup_rcu(const struct dentry *parent,
                                     const struct qstr *name, unsigned *seq);

extern void d_invalidate(struct dentry *);

extern void d_set_d_op(struct dentry *dentry,
                       const struct dentry_operations *op);

extern void d_add(struct dentry *, struct inode *);

/*
 * Directory cache entry type accessor functions.
 */
static inline unsigned __d_entry_type(const struct dentry *dentry)
{
    return dentry->d_flags & DCACHE_ENTRY_TYPE;
}

static inline bool d_is_miss(const struct dentry *dentry)
{
    return __d_entry_type(dentry) == DCACHE_MISS_TYPE;
}

static inline bool d_is_symlink(const struct dentry *dentry)
{
    return __d_entry_type(dentry) == DCACHE_SYMLINK_TYPE;
}

static inline bool d_can_lookup(const struct dentry *dentry)
{
    return __d_entry_type(dentry) == DCACHE_DIRECTORY_TYPE;
}

static inline bool d_is_negative(const struct dentry *dentry)
{
    // TODO: check d_is_whiteout(dentry) also.
    return d_is_miss(dentry);
}

static inline bool d_is_positive(const struct dentry *dentry)
{
    return !d_is_negative(dentry);
}

/*
 * These are the low-level FS interfaces to the dcache..
 */
extern void d_instantiate(struct dentry *, struct inode *);

/**
 * d_backing_inode - Get upper or lower inode we should be using
 * @upper: The upper layer
 *
 * This is the helper that should be used to get at the inode that will be used
 * if this dentry were to be opened as a file.  The inode may be on the upper
 * dentry or it may be on a lower dentry pinned by the upper.
 *
 * Normal filesystems should not use this to access their own inodes.
 */
static inline struct inode *d_backing_inode(const struct dentry *upper)
{
    struct inode *inode = upper->d_inode;

    return inode;
}

extern void d_tmpfile(struct dentry *, struct inode *);

/**
 * d_really_is_negative - Determine if a dentry is really negative (ignoring fallthroughs)
 * @dentry: The dentry in question
 *
 * Returns true if the dentry represents either an absent name or a name that
 * doesn't map to an inode (ie. ->d_inode is NULL).  The dentry could represent
 * a true miss, a whiteout that isn't represented by a 0,0 chardev or a
 * fallthrough marker in an opaque directory.
 *
 * Note!  (1) This should be used *only* by a filesystem to examine its own
 * dentries.  It should not be used to look at some other filesystem's
 * dentries.  (2) It should also be used in combination with d_inode() to get
 * the inode.  (3) The dentry may have something attached to ->d_lower and the
 * type field of the flags may be set to something other than miss or whiteout.
 */
static inline bool d_really_is_negative(const struct dentry *dentry)
{
    return dentry->d_inode == NULL;
}

/**
 * d_really_is_positive - Determine if a dentry is really positive (ignoring fallthroughs)
 * @dentry: The dentry in question
 *
 * Returns true if the dentry represents a name that maps to an inode
 * (ie. ->d_inode is not NULL).  The dentry might still represent a whiteout if
 * that is represented on medium as a 0,0 chardev.
 *
 * Note!  (1) This should be used *only* by a filesystem to examine its own
 * dentries.  It should not be used to look at some other filesystem's
 * dentries.  (2) It should also be used in combination with d_inode() to get
 * the inode.
 */
static inline bool d_really_is_positive(const struct dentry *dentry)
{
    return dentry->d_inode != NULL;
}

static inline int simple_positive(const struct dentry *dentry)
{
    return d_really_is_positive(dentry) && !d_unhashed(dentry);
}

/**
 * d_inode - Get the actual inode of this dentry
 * @dentry: The dentry to query
 *
 * This is the helper normal filesystems should use to get at their own inodes
 * in their own dentries and ignore the layering superimposed upon them.
 */
static inline struct inode *d_inode(const struct dentry *dentry)
{
    return dentry->d_inode;
}

static inline int d_unlinked(const struct dentry *dentry)
{
    return d_unhashed(dentry) && !IS_ROOT(dentry);
}

extern struct dentry *d_alloc_anon(struct super_block *);
extern struct dentry *d_alloc_parallel(struct dentry *, const struct qstr *,
                                       wait_queue_head_t *);

extern void __d_lookup_done(struct dentry *);

static inline void d_lookup_done(struct dentry *dentry)
{
    if (unlikely(d_in_lookup(dentry))) {
        spin_lock(&dentry->d_lock);
        __d_lookup_done(dentry);
        spin_unlock(&dentry->d_lock);
    }
}

static inline bool d_flags_negative(unsigned flags)
{
    return (flags & DCACHE_ENTRY_TYPE) == DCACHE_MISS_TYPE;
}

static inline int cant_mount(const struct dentry *dentry)
{
    return (dentry->d_flags & DCACHE_CANT_MOUNT);
}

static inline bool d_mountpoint(const struct dentry *dentry)
{
    return dentry->d_flags & DCACHE_MOUNTED;
}

static inline bool d_is_autodir(const struct dentry *dentry)
{
    return __d_entry_type(dentry) == DCACHE_AUTODIR_TYPE;
}

static inline bool d_is_dir(const struct dentry *dentry)
{
    return d_can_lookup(dentry) || d_is_autodir(dentry);
}

static inline bool d_is_reg(const struct dentry *dentry)
{
    return __d_entry_type(dentry) == DCACHE_REGULAR_TYPE;
}

/* allocate/de-allocate */
extern struct dentry *d_splice_alias(struct inode *, struct dentry *);
extern struct dentry *d_add_ci(struct dentry *, struct inode *, struct qstr *);
extern struct dentry *d_exact_alias(struct dentry *, struct inode *);
extern struct dentry *d_find_any_alias(struct inode *inode);
extern struct dentry *d_obtain_alias(struct inode *);
extern struct dentry *d_obtain_root(struct inode *);
extern void shrink_dcache_sb(struct super_block *);
extern void shrink_dcache_parent(struct dentry *);
extern void shrink_dcache_for_umount(struct super_block *);

#endif  /* __LINUX_DCACHE_H */
