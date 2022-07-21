// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

//#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#if 0
#include <linux/fscrypt.h>
#include <linux/fsnotify.h>
#endif
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/export.h>
//#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/memblock.h>
#if 0
#include <linux/bit_spinlock.h>
#include <linux/rculist_bl.h>
#endif
#include <linux/list_lru.h>
#include "internal.h"
#if 0
#include "mount.h"
#endif

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __read_mostly;
EXPORT_SYMBOL(names_cachep);

static struct kmem_cache *dentry_cache __read_mostly;

const struct qstr slash_name = QSTR_INIT("/", 1);
EXPORT_SYMBOL(slash_name);

static DEFINE_PER_CPU(long, nr_dentry);
static DEFINE_PER_CPU(long, nr_dentry_unused);
static DEFINE_PER_CPU(long, nr_dentry_negative);

struct external_name {
    union {
        atomic_t count;
        struct rcu_head head;
    } u;
    unsigned char name[];
};

static __initdata unsigned long dhash_entries;
static unsigned int d_hash_shift __read_mostly;
static struct hlist_bl_head *dentry_hashtable __read_mostly;

static inline struct hlist_bl_head *d_hash(unsigned int hash)
{
    return dentry_hashtable + (hash >> d_hash_shift);
}

static void __d_rehash(struct dentry *entry)
{
    struct hlist_bl_head *b = d_hash(entry->d_name.hash);

    hlist_bl_lock(b);
    hlist_bl_add_head_rcu(&entry->d_hash, b);
    hlist_bl_unlock(b);
}

static inline unsigned start_dir_add(struct inode *dir)
{

    for (;;) {
        unsigned n = dir->i_dir_seq;
        if (!(n & 1) && cmpxchg(&dir->i_dir_seq, n, n + 1) == n)
            return n;
        cpu_relax();
    }
}

static inline void end_dir_add(struct inode *dir, unsigned n)
{
    smp_store_release(&dir->i_dir_seq, n + 2);
}

static inline struct external_name *external_name(struct dentry *dentry)
{
    return container_of(dentry->d_name.name, struct external_name, name[0]);
}

static inline int dname_external(const struct dentry *dentry)
{
    return dentry->d_name.name != dentry->d_iname;
}

/*
 * The DCACHE_LRU_LIST bit is set whenever the 'd_lru' entry
 * is in use - which includes both the "real" per-superblock
 * LRU list _and_ the DCACHE_SHRINK_LIST use.
 *
 * The DCACHE_SHRINK_LIST bit is set whenever the dentry is
 * on the shrink list (ie not on the superblock LRU list).
 *
 * The per-cpu "nr_dentry_unused" counters are updated with
 * the DCACHE_LRU_LIST bit.
 *
 * The per-cpu "nr_dentry_negative" counters are only updated
 * when deleted from or added to the per-superblock LRU list, not
 * from/to the shrink list. That is to avoid an unneeded dec/inc
 * pair when moving from LRU to shrink list in select_collect().
 *
 * These helper functions make sure we always follow the
 * rules. d_lock must be held by the caller.
 */
#define D_FLAG_VERIFY(dentry,x) \
    WARN_ON_ONCE(((dentry)->d_flags & (DCACHE_LRU_LIST | DCACHE_SHRINK_LIST)) \
                 != (x))

static void d_lru_add(struct dentry *dentry)
{
#if 0
    D_FLAG_VERIFY(dentry, 0);
    dentry->d_flags |= DCACHE_LRU_LIST;
    this_cpu_inc(nr_dentry_unused);
    if (d_is_negative(dentry))
        this_cpu_inc(nr_dentry_negative);
    WARN_ON_ONCE(!list_lru_add(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
#endif
    panic("%s: END!\n", __func__);
}

static void d_lru_del(struct dentry *dentry)
{
#if 0
    D_FLAG_VERIFY(dentry, DCACHE_LRU_LIST);
    dentry->d_flags &= ~DCACHE_LRU_LIST;
    this_cpu_dec(nr_dentry_unused);
    if (d_is_negative(dentry))
        this_cpu_dec(nr_dentry_negative);
    WARN_ON_ONCE(!list_lru_del(&dentry->d_sb->s_dentry_lru, &dentry->d_lru));
#endif
    panic("%s: END!\n", __func__);
}

/**
 * __d_alloc    -   allocate a dcache entry
 * @sb: filesystem it will belong to
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
static struct dentry *__d_alloc(struct super_block *sb, const struct qstr *name)
{
    struct dentry *dentry;
    char *dname;
    int err;

    dentry = kmem_cache_alloc_lru(dentry_cache, &sb->s_dentry_lru, GFP_KERNEL);
    if (!dentry)
        return NULL;

    /*
     * We guarantee that the inline name is always NUL-terminated.
     * This way the memcpy() done by the name switching in rename
     * will still always have a NUL at the end, even if we might
     * be overwriting an internal NUL character
     */
    dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
    if (unlikely(!name)) {
        name = &slash_name;
        dname = dentry->d_iname;
    } else if (name->len > DNAME_INLINE_LEN-1) {
        size_t size = offsetof(struct external_name, name[1]);
        struct external_name *p =
            kmalloc(size + name->len, GFP_KERNEL_ACCOUNT | __GFP_RECLAIMABLE);
        if (!p) {
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
        atomic_set(&p->u.count, 1);
        dname = p->name;
    } else  {
        dname = dentry->d_iname;
    }

    dentry->d_name.len = name->len;
    dentry->d_name.hash = name->hash;
    memcpy(dname, name->name, name->len);
    dname[name->len] = 0;

    /* Make sure we always see the terminating NUL character */
    smp_store_release(&dentry->d_name.name, dname); /* ^^^ */

    dentry->d_lockref.count = 1;
    dentry->d_flags = 0;
    spin_lock_init(&dentry->d_lock);
    seqcount_spinlock_init(&dentry->d_seq, &dentry->d_lock);
    dentry->d_inode = NULL;
    dentry->d_parent = dentry;
    dentry->d_sb = sb;
    dentry->d_op = NULL;
    dentry->d_fsdata = NULL;
    INIT_HLIST_BL_NODE(&dentry->d_hash);
    INIT_LIST_HEAD(&dentry->d_lru);
    INIT_LIST_HEAD(&dentry->d_subdirs);
    INIT_HLIST_NODE(&dentry->d_u.d_alias);
    INIT_LIST_HEAD(&dentry->d_child);
    d_set_d_op(dentry, dentry->d_sb->s_d_op);

    if (dentry->d_op && dentry->d_op->d_init) {
        err = dentry->d_op->d_init(dentry);
        if (err) {
            if (dname_external(dentry))
                kfree(external_name(dentry));
            kmem_cache_free(dentry_cache, dentry);
            return NULL;
        }
    }

    this_cpu_inc(nr_dentry);
    return dentry;
}

struct dentry *d_alloc_anon(struct super_block *sb)
{
    return __d_alloc(sb, NULL);
}
EXPORT_SYMBOL(d_alloc_anon);

static unsigned d_flags_for_inode(struct inode *inode)
{
    unsigned add_flags = DCACHE_REGULAR_TYPE;

    if (!inode)
        return DCACHE_MISS_TYPE;

    if (S_ISDIR(inode->i_mode)) {
        add_flags = DCACHE_DIRECTORY_TYPE;
        if (unlikely(!(inode->i_opflags & IOP_LOOKUP))) {
            if (unlikely(!inode->i_op->lookup))
                add_flags = DCACHE_AUTODIR_TYPE;
            else
                inode->i_opflags |= IOP_LOOKUP;
        }
        goto type_determined;
    }

    if (unlikely(!(inode->i_opflags & IOP_NOFOLLOW))) {
        if (unlikely(inode->i_op->get_link)) {
            add_flags = DCACHE_SYMLINK_TYPE;
            goto type_determined;
        }
        inode->i_opflags |= IOP_NOFOLLOW;
    }

    if (unlikely(!S_ISREG(inode->i_mode)))
        add_flags = DCACHE_SPECIAL_TYPE;

type_determined:
    if (unlikely(IS_AUTOMOUNT(inode)))
        add_flags |= DCACHE_NEED_AUTOMOUNT;
    return add_flags;
}

static inline void __d_set_inode_and_type(struct dentry *dentry,
                                          struct inode *inode,
                                          unsigned type_flags)
{
    unsigned flags;

    dentry->d_inode = inode;
    flags = READ_ONCE(dentry->d_flags);
    flags &= ~(DCACHE_ENTRY_TYPE | DCACHE_FALLTHRU);
    flags |= type_flags;
    smp_store_release(&dentry->d_flags, flags);
}

static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
    unsigned add_flags = d_flags_for_inode(inode);
    WARN_ON(d_in_lookup(dentry));

    spin_lock(&dentry->d_lock);
    /*
     * Decrement negative dentry count if it was in the LRU list.
     */
    if (dentry->d_flags & DCACHE_LRU_LIST)
        this_cpu_dec(nr_dentry_negative);
    hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
    raw_write_seqcount_begin(&dentry->d_seq);
    __d_set_inode_and_type(dentry, inode, add_flags);
    raw_write_seqcount_end(&dentry->d_seq);
    //fsnotify_update_flags(dentry);
    spin_unlock(&dentry->d_lock);
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */

void d_instantiate(struct dentry *entry, struct inode *inode)
{
    BUG_ON(!hlist_unhashed(&entry->d_u.d_alias));
    if (inode) {
        spin_lock(&inode->i_lock);
        __d_instantiate(entry, inode);
        spin_unlock(&inode->i_lock);
    }
}
EXPORT_SYMBOL(d_instantiate);

struct dentry *d_make_root(struct inode *root_inode)
{
    struct dentry *res = NULL;

    if (root_inode) {
        res = d_alloc_anon(root_inode->i_sb);
        if (res)
            d_instantiate(res, root_inode);
        else
            iput(root_inode);
    }
    return res;
}
EXPORT_SYMBOL(d_make_root);

/*
 * Try to do a lockless dput(), and return whether that was successful.
 *
 * If unsuccessful, we return false, having already taken the dentry lock.
 *
 * The caller needs to hold the RCU read lock, so that the dentry is
 * guaranteed to stay around even if the refcount goes down to zero!
 */
static inline bool fast_dput(struct dentry *dentry)
{
#if 0
    int ret;
    unsigned int d_flags;

    /*
     * If we have a d_op->d_delete() operation, we sould not
     * let the dentry count go to zero, so use "put_or_lock".
     */
    if (unlikely(dentry->d_flags & DCACHE_OP_DELETE))
        return lockref_put_or_lock(&dentry->d_lockref);

    /*
     * .. otherwise, we can try to just decrement the
     * lockref optimistically.
     */
    ret = lockref_put_return(&dentry->d_lockref);

    /*
     * If the lockref_put_return() failed due to the lock being held
     * by somebody else, the fast path has failed. We will need to
     * get the lock, and then check the count again.
     */
    if (unlikely(ret < 0)) {
        spin_lock(&dentry->d_lock);
        if (dentry->d_lockref.count > 1) {
            dentry->d_lockref.count--;
            spin_unlock(&dentry->d_lock);
            return true;
        }
        return false;
    }

    /*
     * If we weren't the last ref, we're done.
     */
    if (ret)
        return true;

    /*
     * Careful, careful. The reference count went down
     * to zero, but we don't hold the dentry lock, so
     * somebody else could get it again, and do another
     * dput(), and we need to not race with that.
     *
     * However, there is a very special and common case
     * where we don't care, because there is nothing to
     * do: the dentry is still hashed, it does not have
     * a 'delete' op, and it's referenced and already on
     * the LRU list.
     *
     * NOTE! Since we aren't locked, these values are
     * not "stable". However, it is sufficient that at
     * some point after we dropped the reference the
     * dentry was hashed and the flags had the proper
     * value. Other dentry users may have re-gotten
     * a reference to the dentry and change that, but
     * our work is done - we can leave the dentry
     * around with a zero refcount.
     *
     * Nevertheless, there are two cases that we should kill
     * the dentry anyway.
     * 1. free disconnected dentries as soon as their refcount
     *    reached zero.
     * 2. free dentries if they should not be cached.
     */
    smp_rmb();
    d_flags = READ_ONCE(dentry->d_flags);
    d_flags &= DCACHE_REFERENCED | DCACHE_LRU_LIST |
            DCACHE_DISCONNECTED | DCACHE_DONTCACHE;

    /* Nothing to do? Dropping the reference was all we needed? */
    if (d_flags == (DCACHE_REFERENCED | DCACHE_LRU_LIST) && !d_unhashed(dentry))
        return true;

    /*
     * Not the fast normal case? Get the lock. We've already decremented
     * the refcount, but we'll need to re-check the situation after
     * getting the lock.
     */
    spin_lock(&dentry->d_lock);

    /*
     * Did somebody else grab a reference to it in the meantime, and
     * we're no longer the last user after all? Alternatively, somebody
     * else could have killed it and marked it dead. Either way, we
     * don't need to do anything else.
     */
    if (dentry->d_lockref.count) {
        spin_unlock(&dentry->d_lock);
        return true;
    }

    /*
     * Re-get the reference we optimistically dropped. We hold the
     * lock, and we just tested that it was zero, so we can just
     * set it to 1.
     */
    dentry->d_lockref.count = 1;
#endif
    panic("%s: END!\n", __func__);
    return false;
}

static inline bool retain_dentry(struct dentry *dentry)
{
    WARN_ON(d_in_lookup(dentry));

    /* Unreachable? Get rid of it */
    if (unlikely(d_unhashed(dentry)))
        return false;

    if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
        return false;

    if (unlikely(dentry->d_flags & DCACHE_OP_DELETE)) {
        if (dentry->d_op->d_delete(dentry))
            return false;
    }

    if (unlikely(dentry->d_flags & DCACHE_DONTCACHE))
        return false;

    /* retain; LRU fodder */
    dentry->d_lockref.count--;
    if (unlikely(!(dentry->d_flags & DCACHE_LRU_LIST)))
        d_lru_add(dentry);
    else if (unlikely(!(dentry->d_flags & DCACHE_REFERENCED)))
        dentry->d_flags |= DCACHE_REFERENCED;
    return true;
}

/*
 * Finish off a dentry we've decided to kill.
 * dentry->d_lock must be held, returns with it unlocked.
 * Returns dentry requiring refcount drop, or NULL if we're done.
 */
static struct dentry *dentry_kill(struct dentry *dentry)
    __releases(dentry->d_lock)
{
#if 0
    struct inode *inode = dentry->d_inode;
    struct dentry *parent = NULL;

    if (inode && unlikely(!spin_trylock(&inode->i_lock)))
        goto slow_positive;

    if (!IS_ROOT(dentry)) {
        parent = dentry->d_parent;
        if (unlikely(!spin_trylock(&parent->d_lock))) {
            parent = __lock_parent(dentry);
            if (likely(inode || !dentry->d_inode))
                goto got_locks;
            /* negative that became positive */
            if (parent)
                spin_unlock(&parent->d_lock);
            inode = dentry->d_inode;
            goto slow_positive;
        }
    }
    __dentry_kill(dentry);
    return parent;

slow_positive:
    spin_unlock(&dentry->d_lock);
    spin_lock(&inode->i_lock);
    spin_lock(&dentry->d_lock);
    parent = lock_parent(dentry);
got_locks:
    if (unlikely(dentry->d_lockref.count != 1)) {
        dentry->d_lockref.count--;
    } else if (likely(!retain_dentry(dentry))) {
        __dentry_kill(dentry);
        return parent;
    }
    /* we are keeping it, after all */
    if (inode)
        spin_unlock(&inode->i_lock);
    if (parent)
        spin_unlock(&parent->d_lock);
    spin_unlock(&dentry->d_lock);
#endif
    panic("%s: END!\n", __func__);
    return NULL;
}

/*
 * dput - release a dentry
 * @dentry: dentry to release
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 */
void dput(struct dentry *dentry)
{
#if 0
    while (dentry) {
        might_sleep();

        rcu_read_lock();
        if (likely(fast_dput(dentry))) {
            rcu_read_unlock();
            return;
        }

        /* Slow case: now with the dentry lock held */
        rcu_read_unlock();

        if (likely(retain_dentry(dentry))) {
            spin_unlock(&dentry->d_lock);
            return;
        }

        dentry = dentry_kill(dentry);
    }
#endif
    pr_warn("%s: END!\n", __func__);
}
EXPORT_SYMBOL(dput);

static void __init dcache_init_early(void)
{
    /* If hashes are distributed across NUMA nodes, defer
     * hash allocation until vmalloc space is available.
     */

    dentry_hashtable =
        alloc_large_system_hash("Dentry cache",
                                sizeof(struct hlist_bl_head),
                                dhash_entries,
                                13,
                                HASH_EARLY | HASH_ZERO,
                                &d_hash_shift,
                                NULL,
                                0,
                                0);
    d_hash_shift = 32 - d_hash_shift;
}

static void __init dcache_init(void)
{
    /*
     * A constructor could be added for stable state like the lists,
     * but it is probably not worth it because of the cache nature
     * of the dcache.
     */
    dentry_cache =
        KMEM_CACHE_USERCOPY(dentry,
                            SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
                            SLAB_MEM_SPREAD|SLAB_ACCOUNT,
                            d_iname);
}

#define IN_LOOKUP_SHIFT 10
static struct hlist_bl_head in_lookup_hashtable[1 << IN_LOOKUP_SHIFT];

static inline struct hlist_bl_head *
in_lookup_hash(const struct dentry *parent, unsigned int hash)
{
    hash += (unsigned long) parent / L1_CACHE_BYTES;
    return in_lookup_hashtable + hash_32(hash, IN_LOOKUP_SHIFT);
}

static inline int dentry_string_cmp(const unsigned char *cs,
                                    const unsigned char *ct, unsigned tcount)
{
    do {
        if (*cs != *ct)
            return 1;
        cs++;
        ct++;
        tcount--;
    } while (tcount);
    return 0;
}

static inline int dentry_cmp(const struct dentry *dentry,
                             const unsigned char *ct, unsigned tcount)
{
    /*
     * Be careful about RCU walk racing with rename:
     * use 'READ_ONCE' to fetch the name pointer.
     *
     * NOTE! Even if a rename will mean that the length
     * was not loaded atomically, we don't care. The
     * RCU walk will check the sequence count eventually,
     * and catch it. And we won't overrun the buffer,
     * because we're reading the name pointer atomically,
     * and a dentry name is guaranteed to be properly
     * terminated with a NUL byte.
     *
     * End result: even if 'len' is wrong, we'll exit
     * early because the data cannot match (there can
     * be no NUL in the ct/tcount data)
     */
    const unsigned char *cs = READ_ONCE(dentry->d_name.name);

    return dentry_string_cmp(cs, ct, tcount);
}

static inline bool d_same_name(const struct dentry *dentry,
                               const struct dentry *parent,
                               const struct qstr *name)
{
    if (likely(!(parent->d_flags & DCACHE_OP_COMPARE))) {
        if (dentry->d_name.len != name->len)
            return false;
        return dentry_cmp(dentry, name->name, name->len) == 0;
    }
    return parent->d_op->d_compare(dentry, dentry->d_name.len,
                                   dentry->d_name.name, name) == 0;
}

/**
 * __d_lookup - search for a dentry (racy)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * __d_lookup is like d_lookup, however it may (rarely) return a
 * false-negative result due to unrelated rename activity.
 *
 * __d_lookup is slightly faster by avoiding rename_lock read seqlock,
 * however it must be used carefully, eg. with a following d_lookup in
 * the case of failure.
 *
 * __d_lookup callers must be commented.
 */
struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name)
{
    unsigned int hash = name->hash;
    struct hlist_bl_head *b = d_hash(hash);
    struct hlist_bl_node *node;
    struct dentry *found = NULL;
    struct dentry *dentry;

    /*
     * Note: There is significant duplication with __d_lookup_rcu which is
     * required to prevent single threaded performance regressions
     * especially on architectures where smp_rmb (in seqcounts) are costly.
     * Keep the two functions in sync.
     */

    /*
     * The hash list is protected using RCU.
     *
     * Take d_lock when comparing a candidate dentry, to avoid races
     * with d_move().
     *
     * It is possible that concurrent renames can mess up our list
     * walk here and result in missing our dentry, resulting in the
     * false-negative result. d_lookup() protects against concurrent
     * renames using rename_lock seqlock.
     *
     * See Documentation/filesystems/path-lookup.txt for more details.
     */
    rcu_read_lock();

    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {

        if (dentry->d_name.hash != hash)
            continue;

        spin_lock(&dentry->d_lock);
        if (dentry->d_parent != parent)
            goto next;
        if (d_unhashed(dentry))
            goto next;

        if (!d_same_name(dentry, parent, name))
            goto next;

        dentry->d_lockref.count++;
        found = dentry;
        spin_unlock(&dentry->d_lock);
        break;
next:
        spin_unlock(&dentry->d_lock);
    }

    rcu_read_unlock();

    return found;
}

/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * Returns: dentry, or NULL
 *
 * d_lookup searches the children of the parent dentry for the name in
 * question. If the dentry is found its reference count is incremented and the
 * dentry is returned. The caller must use dput to free the entry when it has
 * finished using it. %NULL is returned if the dentry does not exist.
 */
struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry;
    unsigned seq;

#if 0
    do {
        seq = read_seqbegin(&rename_lock);
        dentry = __d_lookup(parent, name);
        if (dentry)
            break;
    } while (read_seqretry(&rename_lock, seq));
#else
    dentry = __d_lookup(parent, name);
#endif
    return dentry;
}
EXPORT_SYMBOL(d_lookup);

/* This must be called with d_lock held */
static inline void __dget_dlock(struct dentry *dentry)
{
    dentry->d_lockref.count++;
}

/**
 * d_alloc  -   allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
struct dentry *d_alloc(struct dentry *parent, const struct qstr *name)
{
    struct dentry *dentry = __d_alloc(parent->d_sb, name);
    if (!dentry)
        return NULL;
    spin_lock(&parent->d_lock);
    /*
     * don't need child lock because it is not subject
     * to concurrency here
     */
    __dget_dlock(parent);
    dentry->d_parent = parent;
    list_add(&dentry->d_child, &parent->d_subdirs);
    spin_unlock(&parent->d_lock);

    return dentry;
}
EXPORT_SYMBOL(d_alloc);

static void ___d_drop(struct dentry *dentry)
{
    struct hlist_bl_head *b;
    /*
     * Hashed dentries are normally on the dentry hashtable,
     * with the exception of those newly allocated by
     * d_obtain_root, which are always IS_ROOT:
     */
    if (unlikely(IS_ROOT(dentry)))
        b = &dentry->d_sb->s_roots;
    else
        b = d_hash(dentry->d_name.hash);

    hlist_bl_lock(b);
    __hlist_bl_del(&dentry->d_hash);
    hlist_bl_unlock(b);
}

void __d_drop(struct dentry *dentry)
{
    if (!d_unhashed(dentry)) {
        ___d_drop(dentry);
        dentry->d_hash.pprev = NULL;
        write_seqcount_invalidate(&dentry->d_seq);
    }
}
EXPORT_SYMBOL(__d_drop);

/**
 * d_invalidate - detach submounts, prune dcache, and drop
 * @dentry: dentry to invalidate (aka detach, prune and drop)
 */
void d_invalidate(struct dentry *dentry)
{
    bool had_submounts = false;
    spin_lock(&dentry->d_lock);
    if (d_unhashed(dentry)) {
        spin_unlock(&dentry->d_lock);
        return;
    }
    __d_drop(dentry);
    spin_unlock(&dentry->d_lock);

    /* Negative dentries can be dropped without further checks */
    if (!dentry->d_inode)
        return;

#if 0
    shrink_dcache_parent(dentry);
    for (;;) {
        struct dentry *victim = NULL;
        d_walk(dentry, &victim, find_submount);
        if (!victim) {
            if (had_submounts)
                shrink_dcache_parent(dentry);
            return;
        }
        had_submounts = true;
        detach_mounts(victim);
        dput(victim);
    }
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(d_invalidate);

void d_set_d_op(struct dentry *dentry, const struct dentry_operations *op)
{
    WARN_ON_ONCE(dentry->d_op);
    WARN_ON_ONCE(dentry->d_flags & (DCACHE_OP_HASH  |
                                    DCACHE_OP_COMPARE   |
                                    DCACHE_OP_REVALIDATE    |
                                    DCACHE_OP_WEAK_REVALIDATE   |
                                    DCACHE_OP_DELETE    |
                                    DCACHE_OP_REAL));
    dentry->d_op = op;
    if (!op)
        return;
    if (op->d_hash)
        dentry->d_flags |= DCACHE_OP_HASH;
    if (op->d_compare)
        dentry->d_flags |= DCACHE_OP_COMPARE;
    if (op->d_revalidate)
        dentry->d_flags |= DCACHE_OP_REVALIDATE;
    if (op->d_weak_revalidate)
        dentry->d_flags |= DCACHE_OP_WEAK_REVALIDATE;
    if (op->d_delete)
        dentry->d_flags |= DCACHE_OP_DELETE;
    if (op->d_prune)
        dentry->d_flags |= DCACHE_OP_PRUNE;
    if (op->d_real)
        dentry->d_flags |= DCACHE_OP_REAL;

}
EXPORT_SYMBOL(d_set_d_op);

static inline void __d_add(struct dentry *dentry, struct inode *inode)
{
    struct inode *dir = NULL;
    unsigned n;
    spin_lock(&dentry->d_lock);
    if (unlikely(d_in_lookup(dentry))) {
#if 0
        dir = dentry->d_parent->d_inode;
        n = start_dir_add(dir);
        __d_lookup_done(dentry);
#endif
        panic("%s: d_in_lookup!\n", __func__);
    }
    if (inode) {
#if 0
        unsigned add_flags = d_flags_for_inode(inode);
        hlist_add_head(&dentry->d_u.d_alias, &inode->i_dentry);
        raw_write_seqcount_begin(&dentry->d_seq);
        __d_set_inode_and_type(dentry, inode, add_flags);
        raw_write_seqcount_end(&dentry->d_seq);
        fsnotify_update_flags(dentry);
#endif
        panic("%s: has inode!\n", __func__);
    }
    __d_rehash(dentry);
    if (dir)
        end_dir_add(dir, n);
    spin_unlock(&dentry->d_lock);
    if (inode)
        spin_unlock(&inode->i_lock);
}

/**
 * d_add - add dentry to hash queues
 * @entry: dentry to add
 * @inode: The inode to attach to this dentry
 *
 * This adds the entry to the hash queues and initializes @inode.
 * The entry was actually filled in earlier during d_alloc().
 */
void d_add(struct dentry *entry, struct inode *inode)
{
    if (inode) {
        spin_lock(&inode->i_lock);
    }
    __d_add(entry, inode);
}
EXPORT_SYMBOL(d_add);

/**
 * __d_lookup_rcu - search for a dentry (racy, store-free)
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 * @seqp: returns d_seq value at the point where the dentry was found
 * Returns: dentry, or NULL
 *
 * __d_lookup_rcu is the dcache lookup function for rcu-walk name
 * resolution (store-free path walking) design described in
 * Documentation/filesystems/path-lookup.txt.
 *
 * This is not to be used outside core vfs.
 *
 * __d_lookup_rcu must only be used in rcu-walk mode, ie. with vfsmount lock
 * held, and rcu_read_lock held. The returned dentry must not be stored into
 * without taking d_lock and checking d_seq sequence count against @seq
 * returned here.
 *
 * A refcount may be taken on the found dentry with the d_rcu_to_refcount
 * function.
 *
 * Alternatively, __d_lookup_rcu may be called again to look up the child of
 * the returned dentry, so long as its parent's seqlock is checked after the
 * child is looked up. Thus, an interlocking stepping of sequence lock checks
 * is formed, giving integrity down the path walk.
 *
 * NOTE! The caller *has* to check the resulting dentry against the sequence
 * number we've returned before using any of the resulting dentry state!
 */
struct dentry *__d_lookup_rcu(const struct dentry *parent,
                              const struct qstr *name,
                              unsigned *seqp)
{
    u64 hashlen = name->hash_len;
    const unsigned char *str = name->name;
    struct hlist_bl_head *b = d_hash(hashlen_hash(hashlen));
    struct hlist_bl_node *node;
    struct dentry *dentry;

    /*
     * Note: There is significant duplication with __d_lookup_rcu which is
     * required to prevent single threaded performance regressions
     * especially on architectures where smp_rmb (in seqcounts) are costly.
     * Keep the two functions in sync.
     */

    /*
     * The hash list is protected using RCU.
     *
     * Carefully use d_seq when comparing a candidate dentry, to avoid
     * races with d_move().
     *
     * It is possible that concurrent renames can mess up our list
     * walk here and result in missing our dentry, resulting in the
     * false-negative result. d_lookup() protects against concurrent
     * renames using rename_lock seqlock.
     *
     * See Documentation/filesystems/path-lookup.txt for more details.
     */
    hlist_bl_for_each_entry_rcu(dentry, node, b, d_hash) {
        unsigned seq;

seqretry:
        /*
         * The dentry sequence count protects us from concurrent
         * renames, and thus protects parent and name fields.
         *
         * The caller must perform a seqcount check in order
         * to do anything useful with the returned dentry.
         *
         * NOTE! We do a "raw" seqcount_begin here. That means that
         * we don't wait for the sequence count to stabilize if it
         * is in the middle of a sequence change. If we do the slow
         * dentry compare, we will do seqretries until it is stable,
         * and if we end up with a successful lookup, we actually
         * want to exit RCU lookup anyway.
         *
         * Note that raw_seqcount_begin still *does* smp_rmb(), so
         * we are still guaranteed NUL-termination of ->d_name.name.
         */
        //seq = raw_seqcount_begin(&dentry->d_seq);
        if (dentry->d_parent != parent)
            continue;
        if (d_unhashed(dentry))
            continue;

        if (unlikely(parent->d_flags & DCACHE_OP_COMPARE)) {
            int tlen;
            const char *tname;
            if (dentry->d_name.hash != hashlen_hash(hashlen))
                continue;
            tlen = dentry->d_name.len;
            tname = dentry->d_name.name;
#if 0
            /* we want a consistent (name,len) pair */
            if (read_seqcount_retry(&dentry->d_seq, seq)) {
                cpu_relax();
                goto seqretry;
            }
#endif
            if (parent->d_op->d_compare(dentry, tlen, tname, name) != 0)
                continue;
        } else {
            if (dentry->d_name.hash_len != hashlen)
                continue;
            if (dentry_cmp(dentry, str, hashlen_len(hashlen)) != 0)
                continue;
        }

        *seqp = seq;
        return dentry;
    }
    return NULL;
}

void __init vfs_caches_init_early(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(in_lookup_hashtable); i++)
        INIT_HLIST_BL_HEAD(&in_lookup_hashtable[i]);

    dcache_init_early();
    inode_init_early();
}

void __init vfs_caches_init(void)
{
    names_cachep =
        kmem_cache_create_usercopy("names_cache", PATH_MAX, 0,
                                   SLAB_HWCACHE_ALIGN|SLAB_PANIC,
                                   0, PATH_MAX, NULL);

    dcache_init();
    inode_init();
#if 0
    files_init();
    files_maxfiles_init();
#endif
    mnt_init();
    bdev_cache_init();
#if 0
    chrdev_init();
#endif
}
