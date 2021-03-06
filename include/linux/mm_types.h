/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/mm_types_task.h>

//#include <linux/auxvec.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
//#include <linux/uprobes.h>
#include <linux/rcupdate.h>
#include <linux/page-flags-layout.h>
//#include <linux/workqueue.h>
#include <linux/seqlock.h>

//#include <asm/mmu.h>

#define _struct_page_alignment

struct page {
    unsigned long flags;    /* Atomic flags, some possibly updated asynchronously */

    union {
        struct {    /* Page cache and anonymous pages */
            /**
             * @lru: Pageout list, eg. active_list protected by
             * lruvec->lru_lock.  Sometimes used as a generic list
             * by the page owner.
             */
            struct list_head lru;
            /* See page-flags.h for PAGE_MAPPING_FLAGS */
            struct address_space *mapping;
            pgoff_t index;      /* Our offset within mapping. */
            /**
             * @private: Mapping-private opaque data.
             * Usually used for buffer_heads if PagePrivate.
             * Used for swp_entry_t if PageSwapCache.
             * Indicates order in the buddy system if PageBuddy.
             */
            unsigned long private;
        };
        struct {    /* slab, slob and slub */
            union {
                struct list_head slab_list;
                struct {        /* Partial pages */
                    struct page *next;
                    int pages;  /* Nr of pages left */
                };
            };
            struct kmem_cache *slab_cache; /* not slob */
            /* Double-word boundary */
            void *freelist;             /* first free object */
            union {
                void *s_mem;            /* slab: first object */
                unsigned long counters; /* SLUB */
                struct {                /* SLUB */
                    unsigned inuse:16;
                    unsigned objects:15;
                    unsigned frozen:1;
                };
            };
        };
        struct {    /* Tail pages of compound page */
            unsigned long compound_head;    /* Bit zero is set */

            /* First tail page only */
            unsigned char compound_dtor;
            unsigned char compound_order;
            atomic_t compound_mapcount;
            unsigned int compound_nr; /* 1 << compound_order */
        };
        struct {    /* Second tail page of compound page */
            unsigned long _compound_pad_1;  /* compound_head */
            atomic_t hpage_pinned_refcount;
            /* For both global and memcg */
            struct list_head deferred_list;
        };
        struct {    /* Page table pages */
            unsigned long _pt_pad_1;    /* compound_head */
            pgtable_t pmd_huge_pte; /* protected by page->ptl */
            unsigned long _pt_pad_2;    /* mapping */
            union {
                struct mm_struct *pt_mm; /* x86 pgds only */
                atomic_t pt_frag_refcount; /* powerpc */
            };
            spinlock_t ptl;
        };

        /** @rcu_head: You can use this to free a page by RCU. */
        struct rcu_head rcu_head;
    };

    union {     /* This union is 4 bytes in size. */
        /*
         * If the page can be mapped to userspace, encodes the number
         * of times this page is referenced by a page table.
         */
        atomic_t _mapcount;

        /*
         * If the page is neither PageSlab nor mappable to userspace,
         * the value stored here may help determine what this page
         * is used for.  See page-flags.h for a list of page types
         * which are currently stored here.
         */
        unsigned int page_type;

        unsigned int active;        /* SLAB */
        int units;                  /* SLOB */
    };

    /* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
    atomic_t _refcount;

} _struct_page_alignment;

/**
 * struct folio - Represents a contiguous set of bytes.
 * @flags: Identical to the page flags.
 * @lru: Least Recently Used list; tracks how recently this folio was used.
 * @mapping: The file this page belongs to, or refers to the anon_vma for
 *    anonymous memory.
 * @index: Offset within the file, in units of pages.  For anonymous memory,
 *    this is the index from the beginning of the mmap.
 * @private: Filesystem per-folio data (see folio_attach_private()).
 *    Used for swp_entry_t if folio_test_swapcache().
 * @_mapcount: Do not access this member directly.  Use folio_mapcount() to
 *    find out how many times this folio is mapped by userspace.
 * @_refcount: Do not access this member directly.  Use folio_ref_count()
 *    to find how many references there are to this folio.
 * @memcg_data: Memory Control Group data.
 *
 * A folio is a physically, virtually and logically contiguous set
 * of bytes.  It is a power-of-two in size, and it is aligned to that
 * same power-of-two.  It is at least as large as %PAGE_SIZE.  If it is
 * in the page cache, it is at a file offset which is a multiple of that
 * power-of-two.  It may be mapped into userspace at an address which is
 * at an arbitrary page offset, but its kernel virtual address is aligned
 * to its size.
 */
struct folio {
    /* private: don't document the anon union */
    union {
        struct {
    /* public: */
            unsigned long flags;
            struct list_head lru;
            struct address_space *mapping;
            pgoff_t index;
            void *private;
            atomic_t _mapcount;
            atomic_t _refcount;
    /* private: the union with struct page is transitional */
        };
        struct page page;
    };
};

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT   (order_base_2(sizeof(struct page)))

struct mm_struct {
    struct {
        pgd_t *pgd;

        atomic_long_t pgtables_bytes;   /* PTE page table pages */

        /* Protects page tables and some counters */
        spinlock_t page_table_lock;

        unsigned long start_code, end_code, start_data, end_data;
        unsigned long start_brk, brk, start_stack;

        /**
         * @mm_count: The number of references to &struct mm_struct
         * (@mm_users count as 1).
         *
         * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
         * &struct mm_struct is freed.
         */
        atomic_t mm_count;
    } __randomize_layout;

    /*
     * The mm_cpumask needs to be at the end of mm_struct, because it
     * is dynamically sized based on nr_cpu_ids.
     */
    unsigned long cpu_bitmap[];
};

extern struct mm_struct init_mm;

/*
 * page_private can be used on tail pages.  However, PagePrivate is only
 * checked by the VM on the head page.  So page_private on the tail pages
 * should be used for data that's ancillary to the head page (eg attaching
 * buffer heads to tail pages after attaching buffer heads to the head page)
 */
#define page_private(page)      ((page)->private)

static inline void
set_page_private(struct page *page, unsigned long private)
{
    page->private = private;
}

static inline atomic_t *compound_mapcount_ptr(struct page *page)
{
    return &page[1].compound_mapcount;
}

static inline atomic_t *compound_pincount_ptr(struct page *page)
{
    return &page[2].hpage_pinned_refcount;
}

/**
 * typedef vm_fault_t - Return type for page fault handlers.
 *
 * Page fault handlers return a bitmask of %VM_FAULT values.
 */
typedef __bitwise unsigned int vm_fault_t;

/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
    /* The first cache line has the info for VMA tree walking. */

    unsigned long vm_start;     /* Our start address within vm_mm. */
    unsigned long vm_end;       /* The first byte after our end address
                       within vm_mm. */

    /* linked list of VM areas per task, sorted by address */
    struct vm_area_struct *vm_next, *vm_prev;

    struct rb_node vm_rb;

    /*
     * Largest free memory gap in bytes to the left of this VMA.
     * Either between this VMA and vma->vm_prev, or between one of the
     * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
     * get_unmapped_area find a free area of the right size.
     */
    unsigned long rb_subtree_gap;

    /* Second cache line starts here. */

    struct mm_struct *vm_mm;    /* The address space we belong to. */

    /*
     * Access permissions of this VMA.
     * See vmf_insert_mixed_prot() for discussion.
     */
    pgprot_t vm_page_prot;
    unsigned long vm_flags;     /* Flags, see mm.h. */

    /*
     * For areas with an address space and backing store,
     * linkage into the address_space->i_mmap interval tree.
     *
     * For private anonymous mappings, a pointer to a null terminated string
     * containing the name given to the vma, or NULL if unnamed.
     */

    union {
        struct {
            struct rb_node rb;
            unsigned long rb_subtree_last;
        } shared;
        /*
         * Serialized by mmap_sem. Never use directly because it is
         * valid only when vm_file is NULL. Use anon_vma_name instead.
         */
        struct anon_vma_name *anon_name;
    };

    /*
     * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
     * list, after a COW of one of the file pages.  A MAP_SHARED vma
     * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
     * or brk vma (with NULL file) can only be in an anon_vma list.
     */
    struct list_head anon_vma_chain; /* Serialized by mmap_lock &
                                        page_table_lock */
    struct anon_vma *anon_vma;  /* Serialized by page_table_lock */

    /* Function pointers to deal with this struct. */
    const struct vm_operations_struct *vm_ops;

    /* Information about our backing store: */
    unsigned long vm_pgoff;     /* Offset (within vm_file) in PAGE_SIZE units */
    struct file * vm_file;      /* File we map to (can be NULL). */
    void * vm_private_data;     /* was vm_pte (shared mem) */

    atomic_long_t swap_readahead_info;
    struct vm_region *vm_region;    /* NOMMU mapping region */
#if 0
    struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
#endif
} __randomize_layout;

/**
 * enum fault_flag - Fault flag definitions.
 * @FAULT_FLAG_WRITE: Fault was a write fault.
 * @FAULT_FLAG_MKWRITE: Fault was mkwrite of existing PTE.
 * @FAULT_FLAG_ALLOW_RETRY: Allow to retry the fault if blocked.
 * @FAULT_FLAG_RETRY_NOWAIT: Don't drop mmap_lock and wait when retrying.
 * @FAULT_FLAG_KILLABLE: The fault task is in SIGKILL killable region.
 * @FAULT_FLAG_TRIED: The fault has been tried once.
 * @FAULT_FLAG_USER: The fault originated in userspace.
 * @FAULT_FLAG_REMOTE: The fault is not for current task/mm.
 * @FAULT_FLAG_INSTRUCTION: The fault was during an instruction fetch.
 * @FAULT_FLAG_INTERRUPTIBLE: The fault can be interrupted by non-fatal signals.
 *
 * About @FAULT_FLAG_ALLOW_RETRY and @FAULT_FLAG_TRIED: we can specify
 * whether we would allow page faults to retry by specifying these two
 * fault flags correctly.  Currently there can be three legal combinations:
 *
 * (a) ALLOW_RETRY and !TRIED:  this means the page fault allows retry, and
 *                              this is the first try
 *
 * (b) ALLOW_RETRY and TRIED:   this means the page fault allows retry, and
 *                              we've already tried at least once
 *
 * (c) !ALLOW_RETRY and !TRIED: this means the page fault does not allow retry
 *
 * The unlisted combination (!ALLOW_RETRY && TRIED) is illegal and should never
 * be used.  Note that page faults can be allowed to retry for multiple times,
 * in which case we'll have an initial fault with flags (a) then later on
 * continuous faults with flags (b).  We should always try to detect pending
 * signals before a retry to make sure the continuous page faults can still be
 * interrupted if necessary.
 */
enum fault_flag {
    FAULT_FLAG_WRITE =          1 << 0,
    FAULT_FLAG_MKWRITE =        1 << 1,
    FAULT_FLAG_ALLOW_RETRY =    1 << 2,
    FAULT_FLAG_RETRY_NOWAIT =   1 << 3,
    FAULT_FLAG_KILLABLE =       1 << 4,
    FAULT_FLAG_TRIED =          1 << 5,
    FAULT_FLAG_USER =           1 << 6,
    FAULT_FLAG_REMOTE =         1 << 7,
    FAULT_FLAG_INSTRUCTION =    1 << 8,
    FAULT_FLAG_INTERRUPTIBLE =  1 << 9,
};

static inline void *folio_get_private(struct folio *folio)
{
    return folio->private;
}

#endif /* _LINUX_MM_TYPES_H */
