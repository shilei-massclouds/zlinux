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
#if 0
#include <linux/stringhash.h>
#endif
#include <linux/wait.h>

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

#endif  /* __LINUX_DCACHE_H */
