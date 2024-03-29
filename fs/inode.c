// SPDX-License-Identifier: GPL-2.0-only
/*
 * (C) 1997 Linus Torvalds
 * (C) 1999 Andrea Arcangeli <andrea@suse.de> (dynamic inode allocation)
 */
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#if 0
#include <linux/security.h>
#endif
#include <linux/cdev.h>
#include <linux/memblock.h>
#if 0
#include <linux/fsnotify.h>
#endif
#include <linux/mount.h>
//#include <linux/posix_acl.h>
#include <linux/prefetch.h>
#include <linux/list_lru.h>
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#if 0
#include <linux/iversion.h>
#endif
#include "internal.h"

static struct kmem_cache *inode_cachep __read_mostly;

static __initdata unsigned long ihash_entries;
static unsigned int i_hash_mask __read_mostly;
static unsigned int i_hash_shift __read_mostly;
static __cacheline_aligned_in_smp DEFINE_SPINLOCK(inode_hash_lock);
static struct hlist_head *inode_hashtable __read_mostly;

static DEFINE_PER_CPU(unsigned long, nr_inodes);
static DEFINE_PER_CPU(unsigned long, nr_unused);

static unsigned long hash(struct super_block *sb, unsigned long hashval)
{
    unsigned long tmp;

    tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
        L1_CACHE_BYTES;
    tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> i_hash_shift);
    return tmp & i_hash_mask;
}

static void i_callback(struct rcu_head *head)
{
#if 0
    struct inode *inode = container_of(head, struct inode, i_rcu);
    if (inode->free_inode)
        inode->free_inode(inode);
    else
        free_inode_nonrcu(inode);
#endif
    panic("%s: END!\n", __func__);
}

static int no_open(struct inode *inode, struct file *file)
{
    return -ENXIO;
}

/*
 * Empty aops. Can be used for the cases where the user does not
 * define any of the address_space operations.
 */
const struct address_space_operations empty_aops = {
};
EXPORT_SYMBOL(empty_aops);

/**
 * inode_init_always - perform inode structure initialisation
 * @sb: superblock inode belongs to
 * @inode: inode to initialise
 *
 * These are initializations that need to be done on every inode
 * allocation as the fields are not initialised by slab allocation.
 */
int inode_init_always(struct super_block *sb, struct inode *inode)
{
    static const struct inode_operations empty_iops;
    static const struct file_operations no_open_fops = {.open = no_open};
    struct address_space *const mapping = &inode->i_data;

    inode->i_sb = sb;
    inode->i_blkbits = sb->s_blocksize_bits;
    inode->i_flags = 0;
    atomic64_set(&inode->i_sequence, 0);
    atomic_set(&inode->i_count, 1);
    inode->i_op = &empty_iops;
    inode->i_fop = &no_open_fops;
    inode->i_ino = 0;
    inode->__i_nlink = 1;
    inode->i_opflags = 0;
#if 0
    if (sb->s_xattr)
        inode->i_opflags |= IOP_XATTR;
    i_uid_write(inode, 0);
    i_gid_write(inode, 0);
#endif
    atomic_set(&inode->i_writecount, 0);
    inode->i_size = 0;
    inode->i_write_hint = WRITE_LIFE_NOT_SET;
    inode->i_blocks = 0;
    inode->i_bytes = 0;
    inode->i_generation = 0;
#if 0
    inode->i_pipe = NULL;
    inode->i_cdev = NULL;
#endif
    inode->i_link = NULL;
    inode->i_dir_seq = 0;
    inode->i_rdev = 0;
    inode->dirtied_when = 0;

    spin_lock_init(&inode->i_lock);

    init_rwsem(&inode->i_rwsem);

    atomic_set(&inode->i_dio_count, 0);

    mapping->a_ops = &empty_aops;
    mapping->host = inode;
    mapping->flags = 0;
    mapping->wb_err = 0;
    atomic_set(&mapping->i_mmap_writable, 0);

#if 0
    mapping_set_gfp_mask(mapping, GFP_HIGHUSER_MOVABLE);
    mapping->private_data = NULL;
    mapping->writeback_index = 0;
    init_rwsem(&mapping->invalidate_lock);
    inode->i_private = NULL;
#endif
    inode->i_mapping = mapping;
    INIT_HLIST_HEAD(&inode->i_dentry);  /* buggered by rcu freeing */
#if 0
    inode->i_acl = inode->i_default_acl = ACL_NOT_CACHED;
#endif

#if 0
    inode->i_fsnotify_mask = 0;
    inode->i_flctx = NULL;
#endif
    this_cpu_inc(nr_inodes);

    return 0;
out:
    return -ENOMEM;
}
EXPORT_SYMBOL(inode_init_always);

static struct inode *alloc_inode(struct super_block *sb)
{
    const struct super_operations *ops = sb->s_op;
    struct inode *inode;

    if (ops->alloc_inode)
        inode = ops->alloc_inode(sb);
    else
        inode = alloc_inode_sb(sb, inode_cachep, GFP_KERNEL);

    if (!inode)
        return NULL;

    if (unlikely(inode_init_always(sb, inode))) {
        if (ops->destroy_inode) {
            ops->destroy_inode(inode);
            if (!ops->free_inode)
                return NULL;
        }
        //inode->free_inode = ops->free_inode;
        i_callback(&inode->i_rcu);
        return NULL;
    }

    return inode;
}

/**
 *  new_inode_pseudo    - obtain an inode
 *  @sb: superblock
 *
 *  Allocates a new inode for given superblock.
 *  Inode wont be chained in superblock s_inodes list
 *  This means :
 *  - fs can't be unmount
 *  - quotas, fsnotify, writeback can't work
 */
struct inode *new_inode_pseudo(struct super_block *sb)
{
    struct inode *inode = alloc_inode(sb);

    if (inode) {
        spin_lock(&inode->i_lock);
        inode->i_state = 0;
        spin_unlock(&inode->i_lock);
        INIT_LIST_HEAD(&inode->i_sb_list);
    }
    return inode;
}

/**
 * inode_sb_list_add - add inode to the superblock list of inodes
 * @inode: inode to add
 */
void inode_sb_list_add(struct inode *inode)
{
    spin_lock(&inode->i_sb->s_inode_list_lock);
    list_add(&inode->i_sb_list, &inode->i_sb->s_inodes);
    spin_unlock(&inode->i_sb->s_inode_list_lock);
}
EXPORT_SYMBOL_GPL(inode_sb_list_add);

/**
 *  new_inode   - obtain an inode
 *  @sb: superblock
 *
 *  Allocates a new inode for given superblock. The default gfp_mask
 *  for allocations related to inode->i_mapping is GFP_HIGHUSER_MOVABLE.
 *  If HIGHMEM pages are unsuitable or it is known that pages allocated
 *  for the page cache are not reclaimable or migratable,
 *  mapping_set_gfp_mask() must be called with suitable flags on the
 *  newly created inode's mapping
 *
 */
struct inode *new_inode(struct super_block *sb)
{
    struct inode *inode;

    spin_lock_prefetch(&sb->s_inode_list_lock);

    inode = new_inode_pseudo(sb);
    if (inode)
        inode_sb_list_add(inode);
    return inode;
}
EXPORT_SYMBOL(new_inode);

static void __address_space_init_once(struct address_space *mapping)
{
    xa_init_flags(&mapping->i_pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
    init_rwsem(&mapping->i_mmap_rwsem);
    INIT_LIST_HEAD(&mapping->private_list);
    spin_lock_init(&mapping->private_lock);
    mapping->i_mmap = RB_ROOT_CACHED;
}

static void __inode_add_lru(struct inode *inode, bool rotate)
{
    if (inode->i_state & (I_DIRTY_ALL | I_SYNC | I_FREEING | I_WILL_FREE))
        return;
    if (atomic_read(&inode->i_count))
        return;
    if (!(inode->i_sb->s_flags & SB_ACTIVE))
        return;
    if (!mapping_shrinkable(&inode->i_data))
        return;

    if (list_lru_add(&inode->i_sb->s_inode_lru, &inode->i_lru))
        this_cpu_inc(nr_unused);
    else if (rotate)
        inode->i_state |= I_REFERENCED;
}

/*
 * Called when we're dropping the last reference
 * to an inode.
 *
 * Call the FS "drop_inode()" function, defaulting to
 * the legacy UNIX filesystem behaviour.  If it tells
 * us to evict inode, do so.  Otherwise, retain inode
 * in cache if fs is alive, sync and evict if fs is
 * shutting down.
 */
static void inode_lru_list_del(struct inode *inode)
{
    if (list_lru_del(&inode->i_sb->s_inode_lru, &inode->i_lru))
        this_cpu_dec(nr_unused);
}

static inline void inode_sb_list_del(struct inode *inode)
{
    if (!list_empty(&inode->i_sb_list)) {
        spin_lock(&inode->i_sb->s_inode_list_lock);
        list_del_init(&inode->i_sb_list);
        spin_unlock(&inode->i_sb->s_inode_list_lock);
    }
}

void __destroy_inode(struct inode *inode)
{
    BUG_ON(inode_has_buffers(inode));
    inode_detach_wb(inode);
#if 0
    fsnotify_inode_delete(inode);
    locks_free_lock_context(inode);
#endif
    if (!inode->i_nlink) {
        WARN_ON(atomic_long_read(&inode->i_sb->s_remove_count) == 0);
        atomic_long_dec(&inode->i_sb->s_remove_count);
    }

#if 0 
    if (inode->i_acl && !is_uncached_acl(inode->i_acl))
        posix_acl_release(inode->i_acl);
    if (inode->i_default_acl && !is_uncached_acl(inode->i_default_acl))
        posix_acl_release(inode->i_default_acl);
#endif
    this_cpu_dec(nr_inodes);
}
EXPORT_SYMBOL(__destroy_inode);

static void destroy_inode(struct inode *inode)
{
    const struct super_operations *ops = inode->i_sb->s_op;

    BUG_ON(!list_empty(&inode->i_lru));
    __destroy_inode(inode);
    if (ops->destroy_inode) {
        ops->destroy_inode(inode);
        if (!ops->free_inode)
            return;
    }
    inode->free_inode = ops->free_inode;
    call_rcu(&inode->i_rcu, i_callback);
}

void clear_inode(struct inode *inode)
{
    /*
     * We have to cycle the i_pages lock here because reclaim can be in the
     * process of removing the last page (in __delete_from_page_cache())
     * and we must not free the mapping under it.
     */
    xa_lock_irq(&inode->i_data.i_pages);
    BUG_ON(inode->i_data.nrpages);
    /*
     * Almost always, mapping_empty(&inode->i_data) here; but there are
     * two known and long-standing ways in which nodes may get left behind
     * (when deep radix-tree node allocation failed partway; or when THP
     * collapse_file() failed). Until those two known cases are cleaned up,
     * or a cleanup function is called here, do not BUG_ON(!mapping_empty),
     * nor even WARN_ON(!mapping_empty).
     */
    xa_unlock_irq(&inode->i_data.i_pages);
    BUG_ON(!list_empty(&inode->i_data.private_list));
    BUG_ON(!(inode->i_state & I_FREEING));
    BUG_ON(inode->i_state & I_CLEAR);
    BUG_ON(!list_empty(&inode->i_wb_list));
    /* don't need i_lock here, no concurrent mods to i_state */
    inode->i_state = I_FREEING | I_CLEAR;
}
EXPORT_SYMBOL(clear_inode);

/*
 * Free the inode passed in, removing it from the lists it is still connected
 * to. We remove any pages still attached to the inode and wait for any IO that
 * is still in progress before finally destroying the inode.
 *
 * An inode must already be marked I_FREEING so that we avoid the inode being
 * moved back onto lists if we race with other code that manipulates the lists
 * (e.g. writeback_single_inode). The caller is responsible for setting this.
 *
 * An inode must already be removed from the LRU list before being evicted from
 * the cache. This should occur atomically with setting the I_FREEING state
 * flag, so no inodes here should ever be on the LRU when being evicted.
 */
static void evict(struct inode *inode)
{
    const struct super_operations *op = inode->i_sb->s_op;

    BUG_ON(!(inode->i_state & I_FREEING));
    BUG_ON(!list_empty(&inode->i_lru));

    if (!list_empty(&inode->i_io_list)) {
        //inode_io_list_del(inode);
        panic("%s: i_io_list!\n", __func__);
    }

    inode_sb_list_del(inode);

    /*
     * Wait for flusher thread to be done with the inode so that filesystem
     * does not start destroying it while writeback is still running. Since
     * the inode has I_FREEING set, flusher thread won't start new work on
     * the inode.  We just have to wait for running writeback to finish.
     */
    inode_wait_for_writeback(inode);

    if (op->evict_inode) {
        op->evict_inode(inode);
    } else {
        pr_info("!!!!!! %s: __func__\n", __func__);
        truncate_inode_pages_final(&inode->i_data);
        clear_inode(inode);
    }
    if (S_ISCHR(inode->i_mode) && inode->i_cdev) {
        //cd_forget(inode);
        panic("%s: S_ISCHR!\n", __func__);
    }

    remove_inode_hash(inode);

    spin_lock(&inode->i_lock);
    wake_up_bit(&inode->i_state, __I_NEW);
    BUG_ON(inode->i_state != (I_FREEING | I_CLEAR));
    spin_unlock(&inode->i_lock);

    destroy_inode(inode);
}

static void iput_final(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    const struct super_operations *op = inode->i_sb->s_op;
    unsigned long state;
    int drop;

    WARN_ON(inode->i_state & I_NEW);

    if (op->drop_inode)
        drop = op->drop_inode(inode);
    else
        drop = generic_drop_inode(inode);

    if (!drop && !(inode->i_state & I_DONTCACHE) && (sb->s_flags & SB_ACTIVE)) {
        __inode_add_lru(inode, true);
        spin_unlock(&inode->i_lock);
        return;
    }

    state = inode->i_state;
    if (!drop) {
        WRITE_ONCE(inode->i_state, state | I_WILL_FREE);
        spin_unlock(&inode->i_lock);

        write_inode_now(inode, 1);

        spin_lock(&inode->i_lock);
        state = inode->i_state;
        WARN_ON(state & I_NEW);
        state &= ~I_WILL_FREE;
    }

    WRITE_ONCE(inode->i_state, state | I_FREEING);
    if (!list_empty(&inode->i_lru))
        inode_lru_list_del(inode);
    spin_unlock(&inode->i_lock);

    evict(inode);
}

/**
 *  iput    - put an inode
 *  @inode: inode to put
 *
 *  Puts an inode, dropping its usage count. If the inode use count hits
 *  zero, the inode is then freed and may also be destroyed.
 *
 *  Consequently, iput() can sleep.
 */
void iput(struct inode *inode)
{
    if (!inode)
        return;

    BUG_ON(inode->i_state & I_CLEAR);

 retry:
    if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
        if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
            atomic_inc(&inode->i_count);
            spin_unlock(&inode->i_lock);
            mark_inode_dirty_sync(inode);
            goto retry;
        }
        iput_final(inode);
        panic("%s: END!\n", __func__);
    }
}
EXPORT_SYMBOL(iput);

int generic_delete_inode(struct inode *inode)
{
    return 1;
}
EXPORT_SYMBOL(generic_delete_inode);

/*
 * These are initializations that only need to be done
 * once, because the fields are idempotent across use
 * of the inode, so let the slab aware of that.
 */
void inode_init_once(struct inode *inode)
{
    memset(inode, 0, sizeof(*inode));
    INIT_HLIST_NODE(&inode->i_hash);
    INIT_LIST_HEAD(&inode->i_devices);
    INIT_LIST_HEAD(&inode->i_io_list);
    INIT_LIST_HEAD(&inode->i_wb_list);
    INIT_LIST_HEAD(&inode->i_lru);
    __address_space_init_once(&inode->i_data);
}
EXPORT_SYMBOL(inode_init_once);

/**
 * inc_nlink - directly increment an inode's link count
 * @inode: inode
 *
 * This is a low-level filesystem helper to replace any
 * direct filesystem manipulation of i_nlink.  Currently,
 * it is only here for parity with dec_nlink().
 */
void inc_nlink(struct inode *inode)
{
    if (unlikely(inode->i_nlink == 0)) {
        WARN_ON(!(inode->i_state & I_LINKABLE));
        atomic_long_dec(&inode->i_sb->s_remove_count);
    }

    inode->__i_nlink++;
}
EXPORT_SYMBOL(inc_nlink);

static void init_once(void *foo)
{
    struct inode *inode = (struct inode *) foo;

    inode_init_once(inode);
}

/**
 * inode_init_owner - Init uid,gid,mode for new inode according to posix standards
 * @mnt_userns: User namespace of the mount the inode was created from
 * @inode: New inode
 * @dir: Directory inode
 * @mode: mode of the new inode
 *
 * If the inode has been created through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then take
 * care to map the inode according to @mnt_userns before checking permissions
 * and initializing i_uid and i_gid. On non-idmapped mounts or if permission
 * checking is to be performed on the raw inode simply passs init_user_ns.
 */
void inode_init_owner(struct user_namespace *mnt_userns, struct inode *inode,
                      const struct inode *dir, umode_t mode)
{
    //inode_fsuid_set(inode, mnt_userns);
    if (dir && dir->i_mode & S_ISGID) {
        inode->i_gid = dir->i_gid;

        /* Directories are special, and always inherit S_ISGID */
        if (S_ISDIR(mode))
            mode |= S_ISGID;
#if 0
        else if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP) &&
             !in_group_p(i_gid_into_mnt(mnt_userns, dir)) &&
             !capable_wrt_inode_uidgid(mnt_userns, dir, CAP_FSETID))
            mode &= ~S_ISGID;
#endif
    } else {
        //inode_fsgid_set(inode, mnt_userns);
    }
    inode->i_mode = mode;
}
EXPORT_SYMBOL(inode_init_owner);

/*
 * Each cpu owns a range of LAST_INO_BATCH numbers.
 * 'shared_last_ino' is dirtied only once out of LAST_INO_BATCH allocations,
 * to renew the exhausted range.
 *
 * This does not significantly increase overflow rate because every CPU can
 * consume at most LAST_INO_BATCH-1 unused inode numbers. So there is
 * NR_CPUS*(LAST_INO_BATCH-1) wastage. At 4096 and 1024, this is ~0.1% of the
 * 2^32 range, and is a worst-case. Even a 50% wastage would only increase
 * overflow rate by 2x, which does not seem too significant.
 *
 * On a 32bit, non LFS stat() call, glibc will generate an EOVERFLOW
 * error if st_ino won't fit in target struct field. Use 32bit counter
 * here to attempt to avoid that.
 */
#define LAST_INO_BATCH 1024
static DEFINE_PER_CPU(unsigned int, last_ino);

unsigned int get_next_ino(void)
{
    unsigned int *p = &get_cpu_var(last_ino);
    unsigned int res = *p;

    if (unlikely((res & (LAST_INO_BATCH-1)) == 0)) {
        static atomic_t shared_last_ino;
        int next = atomic_add_return(LAST_INO_BATCH, &shared_last_ino);

        res = next - LAST_INO_BATCH;
    }

    res++;
    /* get_next_ino should not provide a 0 inode number */
    if (unlikely(!res))
        res++;
    *p = res;
    put_cpu_var(last_ino);
    return res;
}
EXPORT_SYMBOL(get_next_ino);

void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
    inode->i_mode = mode;
    if (S_ISCHR(mode)) {
        inode->i_fop = &def_chr_fops;
        inode->i_rdev = rdev;
    } else if (S_ISBLK(mode)) {
        inode->i_fop = &def_blk_fops;
        inode->i_rdev = rdev;
    } else if (S_ISFIFO(mode))
#if 0
        inode->i_fop = &pipefifo_fops;
#endif
        panic("%s: NO FIFO!\n", __func__);
    else if (S_ISSOCK(mode))
        ;   /* leave it no_open_fops */
    else
        printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o) for "
               "inode %s:%lu\n", mode, inode->i_sb->s_id, inode->i_ino);
}
EXPORT_SYMBOL(init_special_inode);

void inode_nohighmem(struct inode *inode)
{
    mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}
EXPORT_SYMBOL(inode_nohighmem);

/*
 * get additional reference to inode; caller must already hold one.
 */
void ihold(struct inode *inode)
{
    WARN_ON(atomic_inc_return(&inode->i_count) < 2);
}
EXPORT_SYMBOL(ihold);

/*
 * If we try to find an inode in the inode hash while it is being
 * deleted, we have to wait until the filesystem completes its
 * deletion before reporting that it isn't found.  This function waits
 * until the deletion _might_ have completed.  Callers are responsible
 * to recheck inode state.
 *
 * It doesn't matter if I_NEW is not set initially, a call to
 * wake_up_bit(&inode->i_state, __I_NEW) after removing from the hash list
 * will DTRT.
 */
static void __wait_on_freeing_inode(struct inode *inode)
{
    panic("%s: END!\n", __func__);
}

/*
 * inode->i_lock must be held
 */
void __iget(struct inode *inode)
{
    atomic_inc(&inode->i_count);
}

/*
 * find_inode_fast is the fast path version of find_inode, see the comment at
 * iget_locked for details.
 */
static struct inode *find_inode_fast(struct super_block *sb,
                                     struct hlist_head *head, unsigned long ino)
{
    struct inode *inode = NULL;

 repeat:
    hlist_for_each_entry(inode, head, i_hash) {
        if (inode->i_ino != ino)
            continue;
        if (inode->i_sb != sb)
            continue;
        spin_lock(&inode->i_lock);
        if (inode->i_state & (I_FREEING|I_WILL_FREE)) {
            __wait_on_freeing_inode(inode);
            goto repeat;
        }
        if (unlikely(inode->i_state & I_CREATING)) {
            spin_unlock(&inode->i_lock);
            return ERR_PTR(-ESTALE);
        }
        __iget(inode);
        spin_unlock(&inode->i_lock);
        return inode;
    }
    return NULL;
}

/**
 * ilookup - search for an inode in the inode cache
 * @sb:     super block of file system to search
 * @ino:    inode number to search for
 *
 * Search for the inode @ino in the inode cache, and if the inode is in the
 * cache, the inode is returned with an incremented reference count.
 */
struct inode *ilookup(struct super_block *sb, unsigned long ino)
{
    struct hlist_head *head = inode_hashtable + hash(sb, ino);
    struct inode *inode;

 again:
    spin_lock(&inode_hash_lock);
    inode = find_inode_fast(sb, head, ino);
    spin_unlock(&inode_hash_lock);

    if (inode) {
        if (IS_ERR(inode))
            return NULL;
        //wait_on_inode(inode);
        if (unlikely(inode_unhashed(inode))) {
            iput(inode);
            goto again;
        }
    }
    return inode;
}
EXPORT_SYMBOL(ilookup);

/**
 *  __insert_inode_hash - hash an inode
 *  @inode: unhashed inode
 *  @hashval: unsigned long value used to locate this object in the
 *      inode_hashtable.
 *
 *  Add an inode to the inode hash for this superblock.
 */
void __insert_inode_hash(struct inode *inode, unsigned long hashval)
{
    struct hlist_head *b = inode_hashtable + hash(inode->i_sb, hashval);

    spin_lock(&inode_hash_lock);
    spin_lock(&inode->i_lock);
    hlist_add_head_rcu(&inode->i_hash, b);
    spin_unlock(&inode->i_lock);
    spin_unlock(&inode_hash_lock);
}
EXPORT_SYMBOL(__insert_inode_hash);

/**
 *  __remove_inode_hash - remove an inode from the hash
 *  @inode: inode to unhash
 *
 *  Remove an inode from the superblock.
 */
void __remove_inode_hash(struct inode *inode)
{
    spin_lock(&inode_hash_lock);
    spin_lock(&inode->i_lock);
    hlist_del_init_rcu(&inode->i_hash);
    spin_unlock(&inode->i_lock);
    spin_unlock(&inode_hash_lock);
}
EXPORT_SYMBOL(__remove_inode_hash);

/*
 * Add inode to LRU if needed (inode is unused and clean).
 *
 * Needs inode->i_lock held.
 */
void inode_add_lru(struct inode *inode)
{
    __inode_add_lru(inode, false);
}


/**
 * iget_locked - obtain an inode from a mounted file system
 * @sb:     super block of file system
 * @ino:    inode number to get
 *
 * Search for the inode specified by @ino in the inode cache and if present
 * return it with an increased reference count. This is for file systems
 * where the inode number is sufficient for unique identification of an inode.
 *
 * If the inode is not in cache, allocate a new inode and return it locked,
 * hashed, and with the I_NEW flag set.  The file system gets to fill it in
 * before unlocking it via unlock_new_inode().
 */
struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
    struct hlist_head *head = inode_hashtable + hash(sb, ino);
    struct inode *inode;
 again:
    spin_lock(&inode_hash_lock);
    inode = find_inode_fast(sb, head, ino);
    spin_unlock(&inode_hash_lock);
    if (inode) {
        if (IS_ERR(inode))
            return NULL;
        wait_on_inode(inode);
        if (unlikely(inode_unhashed(inode))) {
            iput(inode);
            goto again;
        }
        return inode;
    }

    inode = alloc_inode(sb);
    if (inode) {
        struct inode *old;

        spin_lock(&inode_hash_lock);
        /* We released the lock, so.. */
        old = find_inode_fast(sb, head, ino);
        if (!old) {
            inode->i_ino = ino;
            spin_lock(&inode->i_lock);
            inode->i_state = I_NEW;
            hlist_add_head_rcu(&inode->i_hash, head);
            spin_unlock(&inode->i_lock);
            inode_sb_list_add(inode);
            spin_unlock(&inode_hash_lock);

            /* Return the locked inode with I_NEW set, the
             * caller is responsible for filling in the contents
             */
            return inode;
        }

        /*
         * Uhhuh, somebody else created the same inode under
         * us. Use the old inode instead of the one we just
         * allocated.
         */
        spin_unlock(&inode_hash_lock);
        destroy_inode(inode);
        if (IS_ERR(old))
            return NULL;
        inode = old;
        wait_on_inode(inode);
        if (unlikely(inode_unhashed(inode))) {
            iput(inode);
            goto again;
        }

        panic("%s: 1!\n", __func__);
    }

    panic("%s: END!\n", __func__);
}

/**
 * unlock_new_inode - clear the I_NEW state and wake up any waiters
 * @inode:  new inode to unlock
 *
 * Called when the inode is fully initialised to clear the new state of the
 * inode and wake up anyone waiting for the inode to finish initialisation.
 */
void unlock_new_inode(struct inode *inode)
{
    spin_lock(&inode->i_lock);
    WARN_ON(!(inode->i_state & I_NEW));
    inode->i_state &= ~I_NEW & ~I_CREATING;
    smp_mb();
    wake_up_bit(&inode->i_state, __I_NEW);
    spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL(unlock_new_inode);

/**
 * current_time - Return FS time
 * @inode: inode.
 *
 * Return the current time truncated to the time granularity supported by
 * the fs.
 *
 * Note that inode and inode->sb cannot be NULL.
 * Otherwise, the function warns and returns time without truncation.
 */
struct timespec64 current_time(struct inode *inode)
{
    struct timespec64 now;

    ktime_get_coarse_real_ts64(&now);

    if (unlikely(!inode->i_sb)) {
        WARN(1, "current_time() called with uninitialized super_block"
             " in the inode");
        return now;
    }

    return timestamp_truncate(now, inode);
}
EXPORT_SYMBOL(current_time);

/**
 * timestamp_truncate - Truncate timespec to a granularity
 * @t: Timespec
 * @inode: inode being updated
 *
 * Truncate a timespec to the granularity supported by the fs
 * containing the inode. Always rounds down. gran must
 * not be 0 nor greater than a second (NSEC_PER_SEC, or 10^9 ns).
 */
struct timespec64 timestamp_truncate(struct timespec64 t,
                                     struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    unsigned int gran = sb->s_time_gran;

    t.tv_sec = clamp(t.tv_sec, sb->s_time_min, sb->s_time_max);
    if (unlikely(t.tv_sec == sb->s_time_max || t.tv_sec == sb->s_time_min))
        t.tv_nsec = 0;

    /* Avoid division in the common cases 1 ns and 1 s. */
    if (gran == 1)
        ; /* nothing */
    else if (gran == NSEC_PER_SEC)
        t.tv_nsec = 0;
    else if (gran > 1 && gran < NSEC_PER_SEC)
        t.tv_nsec -= t.tv_nsec % gran;
    else
        WARN(1, "invalid file time granularity: %u", gran);
    return t;
}
EXPORT_SYMBOL(timestamp_truncate);

/*
 * Initialize the waitqueues and inode hash table.
 */
void __init inode_init_early(void)
{
    /* If hashes are distributed across NUMA nodes, defer
     * hash allocation until vmalloc space is available.
     */

    inode_hashtable =
        alloc_large_system_hash("Inode-cache",
                                sizeof(struct hlist_head),
                                ihash_entries,
                                14,
                                HASH_EARLY | HASH_ZERO,
                                &i_hash_shift,
                                &i_hash_mask,
                                0,
                                0);
}

void __init inode_init(void)
{
    /* inode slab cache */
    inode_cachep = kmem_cache_create("inode_cache",
                                     sizeof(struct inode),
                                     0,
                                     (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|
                                      SLAB_MEM_SPREAD|SLAB_ACCOUNT),
                                     init_once);

    /* Hash may have been set up in inode_init_early */
}
