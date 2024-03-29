/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/mm_types_task.h>

#include <linux/auxvec.h>
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

#include <asm/mmu.h>

struct file;

#define _struct_page_alignment

#define AT_VECTOR_SIZE \
    (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct page {
	unsigned long flags;		/* Atomic flags, some possibly
                                 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * lruvec->lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			union {
				struct list_head lru;
				/* Or, for the Unevictable "LRU list" slot */
				struct {
					/* Always even, to negate PageTail */
					void *__filler;
					/* Count page's or folio's mlocks */
					unsigned int mlock_count;
				};
			};
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			unsigned long private;
		};
		struct {	/* page_pool used by netstack */
			/**
			 * @pp_magic: magic value to avoid recycling non
			 * page_pool allocated pages.
			 */
			unsigned long pp_magic;
			struct page_pool *pp;
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr;
			union {
				/**
				 * dma_addr_upper: might require a 64-bit
				 * value on 32-bit architectures.
				 */
				unsigned long dma_addr_upper;
				/**
				 * For frag page support, not supported in
				 * 32-bit architectures with 64-bit DMA.
				 */
				atomic_long_t pp_frag_count;
			};
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr; /* 1 << compound_order */
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			/* For both global and memcg */
			struct list_head deferred_list;
		};
		struct {	/* Page table pages */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
			unsigned long _pt_pad_2;	/* mapping */
			union {
				struct mm_struct *pt_mm; /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
#else
			spinlock_t ptl;
#endif
		};
		struct {	/* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			void *zone_device_data;
			/*
			 * ZONE_DEVICE private pages are counted as being
			 * mapped so the next 3 words hold the mapping, index,
			 * and private fields from the source anonymous or
			 * page cache page while the page is migrated to device
			 * private memory.
			 * ZONE_DEVICE MEMORY_DEVICE_FS_DAX pages also
			 * use the mapping, index, and private fields when
			 * pmem backed DAX files are mapped.
			 */
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
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
            union {
                struct list_head lru;
                struct {
                    void *__filler;
                    unsigned int mlock_count;
                };
            };
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
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
    unsigned long val;
} swp_entry_t;

struct anon_vma_name {
    struct kref kref;
    /* The name needs to be at the end because it is dynamically sized. */
    char name[];
};

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT   (order_base_2(sizeof(struct page)))

struct mm_struct {
    struct {
        struct vm_area_struct *mmap;    /* list of VMAs */
        struct rb_root mm_rb;
        u64 vmacache_seqnum;            /* per-thread vmacache */
        unsigned long (*get_unmapped_area)(struct file *filp,
                                           unsigned long addr,
                                           unsigned long len,
                                           unsigned long pgoff,
                                           unsigned long flags);
        unsigned long mmap_base;        /* base of mmap area */
        unsigned long mmap_legacy_base; /* base of mmap area
                                           in bottom-up allocations */
        /* Base addresses for compatible mmap() */
        unsigned long mmap_compat_base;
        unsigned long mmap_compat_legacy_base;
        unsigned long task_size;        /* size of task vm space */
        unsigned long highest_vm_end;   /* highest vma end address */
        pgd_t *pgd;

        /**
         * @membarrier_state: Flags controlling membarrier behavior.
         *
         * This field is close to @pgd to hopefully fit in the same
         * cache-line, which needs to be touched by switch_mm().
         */
        atomic_t membarrier_state;

        /**
         * @mm_users: The number of users including userspace.
         *
         * Use mmget()/mmget_not_zero()/mmput() to modify. When this
         * drops to 0 (i.e. when the task exits and there are no other
         * temporary reference holders), we also release a reference on
         * @mm_count (which may then free the &struct mm_struct if
         * @mm_count also drops to 0).
         */
        atomic_t mm_users;

        /**
         * @mm_count: The number of references to &struct mm_struct
         * (@mm_users count as 1).
         *
         * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
         * &struct mm_struct is freed.
         */
        atomic_t mm_count;

        atomic_long_t pgtables_bytes;   /* PTE page table pages */

        int map_count;          /* number of VMAs */

        spinlock_t page_table_lock; /* Protects page tables and some counters */
        /*
         * With some kernel config, the current mmap_lock's offset
         * inside 'mm_struct' is at 0x120, which is very optimal, as
         * its two hot fields 'count' and 'owner' sit in 2 different
         * cachelines,  and when mmap_lock is highly contended, both
         * of the 2 fields will be accessed frequently, current layout
         * will help to reduce cache bouncing.
         *
         * So please be careful with adding new fields before
         * mmap_lock, which can easily push the 2 fields into one
         * cacheline.
         */
        struct rw_semaphore mmap_lock;

        struct list_head mmlist; /* List of maybe swapped mm's. These
                                  * are globally strung together off
                                  * init_mm.mmlist, and are protected
                                  * by mmlist_lock */

        unsigned long hiwater_rss; /* High-watermark of RSS usage */
        unsigned long hiwater_vm;  /* High-water virtual memory usage */

        unsigned long total_vm;    /* Total pages mapped */
        unsigned long locked_vm;   /* Pages that have PG_mlocked set */
        atomic64_t    pinned_vm;   /* Refcount permanently increased */
        unsigned long data_vm;     /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
        unsigned long exec_vm;     /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
        unsigned long stack_vm;    /* VM_STACK */
        unsigned long def_flags;

        /**
         * @write_protect_seq: Locked when any thread is write
         * protecting pages mapped by this mm to enforce a later COW,
         * for instance during page table copying for fork().
         */
        seqcount_t write_protect_seq;

        spinlock_t arg_lock; /* protect the below fields */

        unsigned long start_code, end_code, start_data, end_data;
        unsigned long start_brk, brk, start_stack;
        unsigned long arg_start, arg_end, env_start, env_end;

        unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

        /*
         * Special counters, in some configurations protected by the
         * page_table_lock, in other configurations by being atomic.
         */
        struct mm_rss_stat rss_stat;

        struct linux_binfmt *binfmt;

        /* Architecture-specific MM context */
        mm_context_t context;

        unsigned long flags; /* Must use atomic bitops to access */

        spinlock_t  ioctx_lock;
        struct kioctx_table __rcu   *ioctx_table;

        struct user_namespace *user_ns;

        /* store ref to file /proc/<pid>/exe symlink points to */
        struct file __rcu *exe_file;

        struct mmu_notifier_subscriptions *notifier_subscriptions;

        /*
         * An operation with batched TLB flushing is going on. Anything
         * that can move process memory needs to flush the TLB when
         * moving a PROT_NONE or PROT_NUMA mapped page.
         */
        atomic_t tlb_flush_pending;

        atomic_long_t hugetlb_usage;

#if 0
        struct work_struct async_put_work;
#endif
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
    return &page[1].compound_pincount;
}

/**
 * typedef vm_fault_t - Return type for page fault handlers.
 *
 * Page fault handlers return a bitmask of %VM_FAULT values.
 */
typedef __bitwise unsigned int vm_fault_t;

#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};

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
    struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
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

/**
 * enum vm_fault_reason - Page fault handlers return a bitmask of
 * these values to tell the core VM what happened when handling the
 * fault. Used to decide whether a process gets delivered SIGBUS or
 * just gets major/minor fault counters bumped up.
 *
 * @VM_FAULT_OOM:       Out Of Memory
 * @VM_FAULT_SIGBUS:        Bad access
 * @VM_FAULT_MAJOR:     Page read from storage
 * @VM_FAULT_WRITE:     Special case for get_user_pages
 * @VM_FAULT_HWPOISON:      Hit poisoned small page
 * @VM_FAULT_HWPOISON_LARGE:    Hit poisoned large page. Index encoded
 *              in upper bits
 * @VM_FAULT_SIGSEGV:       segmentation fault
 * @VM_FAULT_NOPAGE:        ->fault installed the pte, not return page
 * @VM_FAULT_LOCKED:        ->fault locked the returned page
 * @VM_FAULT_RETRY:     ->fault blocked, must retry
 * @VM_FAULT_FALLBACK:      huge page fault failed, fall back to small
 * @VM_FAULT_DONE_COW:      ->fault has fully handled COW
 * @VM_FAULT_NEEDDSYNC:     ->fault did not modify page tables and needs
 *              fsync() to complete (for synchronous page faults
 *              in DAX)
 * @VM_FAULT_HINDEX_MASK:   mask HINDEX value
 *
 */
enum vm_fault_reason {
    VM_FAULT_OOM            = (__force vm_fault_t)0x000001,
    VM_FAULT_SIGBUS         = (__force vm_fault_t)0x000002,
    VM_FAULT_MAJOR          = (__force vm_fault_t)0x000004,
    VM_FAULT_WRITE          = (__force vm_fault_t)0x000008,
    VM_FAULT_HWPOISON       = (__force vm_fault_t)0x000010,
    VM_FAULT_HWPOISON_LARGE = (__force vm_fault_t)0x000020,
    VM_FAULT_SIGSEGV        = (__force vm_fault_t)0x000040,
    VM_FAULT_NOPAGE         = (__force vm_fault_t)0x000100,
    VM_FAULT_LOCKED         = (__force vm_fault_t)0x000200,
    VM_FAULT_RETRY          = (__force vm_fault_t)0x000400,
    VM_FAULT_FALLBACK       = (__force vm_fault_t)0x000800,
    VM_FAULT_DONE_COW       = (__force vm_fault_t)0x001000,
    VM_FAULT_NEEDDSYNC      = (__force vm_fault_t)0x002000,
    VM_FAULT_HINDEX_MASK    = (__force vm_fault_t)0x0f0000,
};

#define VM_FAULT_ERROR \
    (VM_FAULT_OOM | VM_FAULT_SIGBUS | \
     VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON | \
     VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)

struct vm_special_mapping {
    const char *name;   /* The name, e.g. "[vdso]". */

    /*
     * If .fault is not provided, this points to a
     * NULL-terminated array of pages that back the special mapping.
     *
     * This must not be NULL unless .fault is provided.
     */
    struct page **pages;

    /*
     * If non-NULL, then this is called to resolve page faults
     * on the special mapping.  If used, .pages is not checked.
     */
    vm_fault_t (*fault)(const struct vm_special_mapping *sm,
                        struct vm_area_struct *vma,
                        struct vm_fault *vmf);

    int (*mremap)(const struct vm_special_mapping *sm,
                  struct vm_area_struct *new_vma);
};

static inline void *folio_get_private(struct folio *folio)
{
    return folio->private;
}

static inline atomic_t *folio_mapcount_ptr(struct folio *folio)
{
    struct page *tail = &folio->page + 1;
    return &tail->compound_mapcount;
}

/* Pointer magic because the dynamic array size confuses some compilers. */
static inline void mm_init_cpumask(struct mm_struct *mm)
{
    unsigned long cpu_bitmap = (unsigned long)mm;

    cpu_bitmap += offsetof(struct mm_struct, cpu_bitmap);
    cpumask_clear((struct cpumask *)cpu_bitmap);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
    return (struct cpumask *)&mm->cpu_bitmap;
}


struct mmu_gather;
extern void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_gather_mmu_fullmm(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_finish_mmu(struct mmu_gather *tlb);

#endif /* _LINUX_MM_TYPES_H */
