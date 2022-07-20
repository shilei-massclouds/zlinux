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
#include <linux/cdev.h>
#endif
#include <linux/memblock.h>
#if 0
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>
#endif
#include <linux/prefetch.h>
#include <linux/list_lru.h>
#if 0
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#include <linux/iversion.h>
#include "internal.h"
#endif

static struct kmem_cache *inode_cachep __read_mostly;

static DEFINE_PER_CPU(unsigned long, nr_inodes);

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
#if 0
    xa_init_flags(&mapping->i_pages, XA_FLAGS_LOCK_IRQ | XA_FLAGS_ACCOUNT);
    init_rwsem(&mapping->i_mmap_rwsem);
    INIT_LIST_HEAD(&mapping->private_list);
    spin_lock_init(&mapping->private_lock);
    mapping->i_mmap = RB_ROOT_CACHED;
#endif
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

    panic("%s: END!\n", __func__);
#if 0
    BUG_ON(inode->i_state & I_CLEAR);
retry:
    if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {
        if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
            atomic_inc(&inode->i_count);
            spin_unlock(&inode->i_lock);
            trace_writeback_lazytime_iput(inode);
            mark_inode_dirty_sync(inode);
            goto retry;
        }
        iput_final(inode);
    }
#endif
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
    //__address_space_init_once(&inode->i_data);
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

static __initdata unsigned long ihash_entries;
static unsigned int i_hash_mask __read_mostly;
static unsigned int i_hash_shift __read_mostly;
static struct hlist_head *inode_hashtable __read_mostly;

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
