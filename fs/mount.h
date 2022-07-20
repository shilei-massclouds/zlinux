/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/mount.h>
#if 0
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>
#endif

struct mnt_namespace {
    struct ns_common    ns;
    struct mount *  root;
    /*
     * Traversal and modification of .list is protected by either
     * - taking namespace_sem for write, OR
     * - taking namespace_sem for read AND taking .ns_lock.
     */
    struct list_head    list;
    spinlock_t      ns_lock;
    struct user_namespace   *user_ns;
    struct ucounts      *ucounts;
    u64         seq;    /* Sequence number to prevent loops */
    wait_queue_head_t poll;
    u64 event;
    unsigned int        mounts; /* # of mounts in the namespace */
    unsigned int        pending_mounts;
} __randomize_layout;

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    union {
        struct rcu_head mnt_rcu;
        struct llist_node mnt_llist;
    };
    struct mnt_pcp __percpu *mnt_pcp;
    struct list_head mnt_mounts;    /* list of children, anchored here */
    struct list_head mnt_child; /* and going through their mnt_child */
    struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
    const char *mnt_devname;    /* Name of device e.g. /dev/dsk/hda1 */
    struct list_head mnt_list;
    struct list_head mnt_expire;    /* link in fs-specific expiry list */
    struct list_head mnt_share; /* circular list of shared mounts */
    struct list_head mnt_slave_list;/* list of slave mounts */
    struct list_head mnt_slave; /* slave list entry */
    struct mount *mnt_master;   /* slave is on master->mnt_slave_list */
    struct mnt_namespace *mnt_ns;   /* containing namespace */
    struct mountpoint *mnt_mp;  /* where is it mounted */
    union {
        struct hlist_node mnt_mp_list;  /* list mounts with the same mountpoint */
        struct hlist_node mnt_umount;
    };
    struct list_head mnt_umounting; /* list entry for umount propagation */
#if 0
    struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
    __u32 mnt_fsnotify_mask;
#endif
    int mnt_id;         /* mount identifier */
    int mnt_group_id;       /* peer group identifier */
    int mnt_expiry_mark;        /* true if marked for expiry */
    struct hlist_head mnt_pins;
    struct hlist_head mnt_stuck_children;
} __randomize_layout;

struct mnt_pcp {
    int mnt_count;
    int mnt_writers;
};

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
    refcount_inc(&ns->ns.count);
}
