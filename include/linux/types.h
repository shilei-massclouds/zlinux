/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#define __EXPORTED_HEADERS__
#include <uapi/linux/types.h>

#ifndef __ASSEMBLY__

#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]

typedef _Bool           bool;

typedef __kernel_ulong_t    ino_t;

typedef __kernel_pid_t      pid_t;

typedef u32         nlink_t;

/*
 * The following typedefs are also protected by individual ifdefs for
 * historical reasons:
 */
#ifndef _SIZE_T
#define _SIZE_T
typedef __kernel_size_t     size_t;
#endif

#ifndef _SSIZE_T
#define _SSIZE_T
typedef __kernel_ssize_t    ssize_t;
#endif

#ifndef _PTRDIFF_T
#define _PTRDIFF_T
typedef __kernel_ptrdiff_t  ptrdiff_t;
#endif

#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__

typedef u8          u_int8_t;
typedef s8          int8_t;
typedef u16         u_int16_t;
typedef s16         int16_t;
typedef u32         u_int32_t;
typedef s32         int32_t;

#endif /* !(__BIT_TYPES_DEFINED__) */

typedef u8          uint8_t;
typedef u16         uint16_t;
typedef u32         uint32_t;

#if defined(__GNUC__)
typedef u64         uint64_t;
typedef u64         u_int64_t;
typedef s64         int64_t;
#endif

/*
 * The type of an index into the pagecache.
 */
#define pgoff_t unsigned long

typedef u64 phys_addr_t;

typedef u64 dma_addr_t;

typedef unsigned long   uintptr_t;

typedef phys_addr_t resource_size_t;

typedef unsigned int __bitwise gfp_t;
typedef unsigned int __bitwise slab_flags_t;
typedef unsigned int __bitwise fmode_t;

typedef struct {
    int counter;
} atomic_t;

typedef struct {
    s64 counter;
} atomic64_t;

struct list_head {
    struct list_head *next, *prev;
};

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define ATOMIC_INIT(i) { (i) }

/**
 * struct callback_head - callback structure for use with RCU and task_work
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 *
 * The struct is aligned to size of pointer. On most architectures it happens
 * naturally due ABI requirements, but some architectures (like CRIS) have
 * weird ABI and we need to ask it explicitly.
 *
 * The alignment is required to guarantee that bit 0 of @next will be
 * clear under normal conditions -- as long as we use call_rcu() or
 * call_srcu() to queue the callback.
 *
 * This guarantee is important for few reasons:
 *  - future call_rcu_lazy() will make use of lower bits in the pointer;
 *  - the structure shares storage space in struct page with @compound_head,
 *    which encode PageTail() in bit 0. The guarantee is needed to avoid
 *    false-positive PageTail().
 */
struct callback_head {
    struct callback_head *next;
    void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head

typedef void (*rcu_callback_t)(struct rcu_head *head);

/*
 * This type is the placeholder for a hardware interrupt number. It has to be
 * big enough to enclose whatever representation is used by a given platform.
 */
typedef unsigned long irq_hw_number_t;

typedef __kernel_mode_t     mode_t;
typedef unsigned short      umode_t;

typedef __kernel_uid32_t    uid_t;
typedef __kernel_gid32_t    gid_t;
typedef __kernel_uid16_t    uid16_t;
typedef __kernel_gid16_t    gid16_t;

/**
 * The type used for indexing onto a disc or disc partition.
 *
 * Linux always considers sectors to be 512 bytes long independently
 * of the devices real block size.
 *
 * blkcnt_t is the type of the inode's block count.
 */
typedef u64 sector_t;
typedef u64 blkcnt_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t      dev_t;
typedef __kernel_loff_t     loff_t;
typedef __kernel_off_t      off_t;

/* bsd */
typedef unsigned char       u_char;
typedef unsigned short      u_short;
typedef unsigned int        u_int;
typedef unsigned long       u_long;

/* sysv */
typedef unsigned char       unchar;
typedef unsigned short      ushort;
typedef unsigned int        uint;
typedef unsigned long       ulong;

typedef __kernel_clockid_t  clockid_t;

typedef void (*rcu_callback_t)(struct rcu_head *head);
typedef void (*call_rcu_func_t)(struct rcu_head *head, rcu_callback_t func);

typedef void (*swap_r_func_t)(void *a, void *b, int size,
                              const void *priv);
typedef void (*swap_func_t)(void *a, void *b, int size);

typedef int (*cmp_r_func_t)(const void *a, const void *b,
                            const void *priv);
typedef int (*cmp_func_t)(const void *a, const void *b);

#endif /* __ASSEMBLY__ */

#endif /* _LINUX_TYPES_H */
