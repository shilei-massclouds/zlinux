/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/mmdebug.h>
#include <linux/gfp.h>
#include <linux/bug.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/rbtree.h>
#include <linux/atomic.h>
//#include <linux/debug_locks.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/range.h>
#include <linux/pfn.h>
#include <linux/percpu-refcount.h>
#if 0
#include <linux/bit_spinlock.h>
#include <linux/shrinker.h>
#include <linux/page_ext.h>
#endif
#include <linux/resource.h>
#include <linux/err.h>
#include <linux/page-flags.h>
#include <linux/page_ref.h>
#include <linux/memremap.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <linux/jump_label.h>

#include <asm/page.h>

struct mempolicy;
struct anon_vma;
struct anon_vma_chain;
struct user_struct;
struct pt_regs;

#define randomize_va_space 0

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
#define PAGE_ALIGNED(addr)  IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

/* Page flags: | [SECTION] | [NODE] | ZONE | [LAST_CPUPID] | ... | FLAGS | */
#define SECTIONS_PGOFF      ((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF         (SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF         (NODES_PGOFF - ZONES_WIDTH)
#define LAST_CPUPID_PGOFF   (ZONES_PGOFF - LAST_CPUPID_WIDTH)

#define NODES_PGSHIFT       (NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT       (ZONES_PGOFF * (ZONES_WIDTH != 0))
#define LAST_CPUPID_PGSHIFT (LAST_CPUPID_PGOFF * (LAST_CPUPID_WIDTH != 0))

#define ZONES_MASK          ((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK          ((1UL << NODES_WIDTH) - 1)
#define LAST_CPUPID_MASK    ((1UL << LAST_CPUPID_SHIFT) - 1)

#define ZONEID_SHIFT (NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF ((NODES_PGOFF < ZONES_PGOFF)? NODES_PGOFF : ZONES_PGOFF)

#define ZONEID_MASK ((1UL << ZONEID_SHIFT) - 1)

#define ZONEID_PGSHIFT (ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#ifndef lm_alias
#define lm_alias(x) __va(__pa_symbol(x))
#endif

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 */
#define VM_NONE     0x00000000

#define VM_READ     0x00000001  /* currently active flags */
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004
#define VM_SHARED   0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD  0x00000010  /* limits for mprotect() etc */
#define VM_MAYWRITE 0x00000020
#define VM_MAYEXEC  0x00000040
#define VM_MAYSHARE 0x00000080

#define VM_GROWSDOWN    0x00000100  /* general info on the segment */
#define VM_UFFD_MISSING 0x00000200  /* missing pages tracking */
#define VM_PFNMAP       0x00000400  /* Page-ranges managed
                                       without "struct page", just pure PFN */
#define VM_UFFD_WP      0x00001000  /* wrprotect pages tracking */

#define VM_LOCKED       0x00002000
#define VM_IO           0x00004000  /* Memory mapped I/O or similar */

                                    /* Used by sys_madvise() */
#define VM_SEQ_READ     0x00008000  /* App will access data sequentially */
#define VM_RAND_READ    0x00010000  /* App will not benefit
                                       from clustered reads */
#define VM_DONTCOPY     0x00020000  /* Do not copy this vma on fork */
#define VM_DONTEXPAND   0x00040000  /* Cannot expand with mremap() */
#define VM_LOCKONFAULT  0x00080000  /* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT      0x00100000  /* Is a VM accounted object */
#define VM_NORESERVE    0x00200000  /* should the VM suppress accounting */
#define VM_HUGETLB      0x00400000  /* Huge TLB Page VM */
#define VM_SYNC         0x00800000  /* Synchronous page faults */
#define VM_ARCH_1       0x01000000  /* Architecture-specific flag */
#define VM_WIPEONFORK   0x02000000  /* Wipe VMA contents in child. */
#define VM_DONTDUMP     0x04000000  /* Do not include in the core dump */

#define VM_SOFTDIRTY    0

#define VM_MIXEDMAP     0x10000000  /* Can contain "struct page"
                                       and pure PFN pages */
#define VM_HUGEPAGE     0x20000000  /* MADV_HUGEPAGE marked this vma */
#define VM_NOHUGEPAGE   0x40000000  /* MADV_NOHUGEPAGE marked this vma */
#define VM_MERGEABLE    0x80000000  /* KSM may merge identical pages */

#define VM_GROWSUP VM_NONE

/* This mask defines which mm->def_flags a process can inherit its parent */
#define VM_INIT_DEF_MASK    VM_NOHUGEPAGE

/* Common data flag combinations */
#define VM_DATA_FLAGS_TSK_EXEC \
    (VM_READ | VM_WRITE | TASK_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#define VM_DATA_FLAGS_NON_EXEC \
    (VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#define VM_DATA_FLAGS_EXEC \
    (VM_READ | VM_WRITE | VM_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

/* This mask is used to clear all the VMA flags used by mlock */
#define VM_LOCKED_CLEAR_MASK    (~(VM_LOCKED | VM_LOCKONFAULT))

#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS

#define VM_STACK        VM_GROWSDOWN
#define VM_STACK_FLAGS  (VM_STACK | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)

/*
 * Special vmas that are non-mergable, non-mlock()able.
 */
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)

/* VMA basic access permission flags */
#define VM_ACCESS_FLAGS (VM_READ | VM_WRITE | VM_EXEC)

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP   (VM_RAND_READ | VM_SEQ_READ)

/*
 * Default maximum number of active map areas, this limits the number of vmas
 * per mm struct. Users can overwrite this number by sysctl but there is a
 * problem.
 *
 * When a program's coredump is generated as ELF format, a section is created
 * per a vma. In ELF, the number of sections is represented in unsigned short.
 * This means the number of sections should be smaller than 65535 at coredump.
 * Because the kernel adds some informative sections to a image of program at
 * generating coredump, we need some margin. The number of extra sections is
 * 1-3 now and depends on arch. We use "5" as safe margin, here.
 *
 * ELF extended numbering allows more than 65535 sections, so 16-bit bound is
 * not a hard limit any more. Although some userspace tools can be surprised by
 * that.
 */
#define MAPCOUNT_ELF_CORE_MARGIN    (5)
#define DEFAULT_MAX_MAP_COUNT       (USHRT_MAX - MAPCOUNT_ELF_CORE_MARGIN)

extern int sysctl_max_map_count;

typedef unsigned long vm_flags_t;

extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
    max_mapnr = limit;
}

void free_area_init(unsigned long *max_zone_pfn);

extern void get_pfn_range_for_nid(unsigned int nid,
                                  unsigned long *start_pfn, unsigned long *end_pfn);

/* This function must be updated when the size of struct page grows above 80
 * or reduces below 56. The idea that compiler optimizes out switch()
 * statement, and only leaves move/store instructions. Also the compiler can
 * combine write statements if they are both assignments and can be reordered,
 * this can result in several of the writes here being dropped.
 */
#define mm_zero_struct_page(pp) __mm_zero_struct_page(pp)
static inline void __mm_zero_struct_page(struct page *page)
{
    unsigned long *_pp = (void *)page;

     /* Check that struct page is either 56, 64, 72, or 80 bytes */
    BUILD_BUG_ON(sizeof(struct page) & 7);
    //BUILD_BUG_ON(sizeof(struct page) < 56);
    BUILD_BUG_ON(sizeof(struct page) > 80);

    switch (sizeof(struct page)) {
    case 80:
        _pp[9] = 0;
        fallthrough;
    case 72:
        _pp[8] = 0;
        fallthrough;
    case 64:
        _pp[7] = 0;
        fallthrough;
    case 56:
        _pp[6] = 0;
        _pp[5] = 0;
        _pp[4] = 0;
        _pp[3] = 0;
        _pp[2] = 0;
        _pp[1] = 0;
        _pp[0] = 0;
    }
}

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
    page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
    page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
    page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
    page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void
set_page_links(struct page *page, enum zone_type zone,
               unsigned long node, unsigned long pfn)
{
    set_page_zone(page, zone);
    set_page_node(page, node);
}

static inline int page_cpupid_last(struct page *page)
{
    return (page->flags >> LAST_CPUPID_PGSHIFT) & LAST_CPUPID_MASK;
}

static inline void page_cpupid_reset_last(struct page *page)
{
    page->flags |= LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT;
}

/*
 * The atomic page->_mapcount, starts from -1: so that transitions
 * both from it and to it can be tracked, using atomic_inc_and_test
 * and atomic_add_negative(-1).
 */
static inline void page_mapcount_reset(struct page *page)
{
    atomic_set(&(page)->_mapcount, -1);
}

static inline enum zone_type page_zonenum(const struct page *page)
{
    return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

static inline int page_to_nid(const struct page *page)
{
    struct page *p = (struct page *)page;

    return (PF_POISONED_CHECK(p)->flags >> NODES_PGSHIFT) & NODES_MASK;
}

static inline struct zone *page_zone(const struct page *page)
{
    return &NODE_DATA(page_to_nid(page))->node_zones[page_zonenum(page)];
}

extern void mem_init(void);
extern void mem_init_print_info(void);

extern atomic_long_t _totalram_pages;

static inline void totalram_pages_add(long count)
{
    atomic_long_add(count, &_totalram_pages);
}

extern void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);

extern void *high_memory;

/*
 * The identification function is mainly used by the buddy allocator for
 * determining if two pages could be buddies. We are not really identifying
 * the zone since we could be using the section number id if we do not have
 * node id available in page flags.
 * We only guarantee that it will return the same value for two combinable
 * pages in a zone.
 */
static inline int page_zone_id(struct page *page)
{
    return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

extern void setup_per_cpu_pageset(void);

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
static inline bool want_init_on_alloc(gfp_t flags)
{
    if (static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, &init_on_alloc))
        return true;

    return flags & __GFP_ZERO;
}

DECLARE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_FREE_DEFAULT_ON, init_on_free);
static inline bool want_init_on_free(void)
{
    return static_branch_maybe(CONFIG_INIT_ON_FREE_DEFAULT_ON, &init_on_free);
}

static inline u8 page_kasan_tag(const struct page *page)
{
    return 0xff;
}

static __always_inline void *lowmem_page_address(const struct page *page)
{
    return page_to_virt(page);
}

#define page_address(page) lowmem_page_address(page)

/* Keep the enum in sync with compound_page_dtors array in mm/page_alloc.c */
enum compound_dtor_id {
    NULL_COMPOUND_DTOR,
    COMPOUND_PAGE_DTOR,
    HUGETLB_PAGE_DTOR,
    NR_COMPOUND_DTORS,
};

static inline void
set_compound_page_dtor(struct page *page, enum compound_dtor_id compound_dtor)
{
    VM_BUG_ON_PAGE(compound_dtor >= NR_COMPOUND_DTORS, page);
    page[1].compound_dtor = compound_dtor;
}

static inline unsigned int compound_order(struct page *page)
{
    if (!PageHead(page))
        return 0;
    return page[1].compound_order;
}

static inline bool hpage_pincount_available(struct page *page)
{
    /*
     * Can the page->hpage_pinned_refcount field be used? That field is in
     * the 3rd page of the compound page, so the smallest (2-page) compound
     * pages cannot support it.
     */
    page = compound_head(page);
    return PageCompound(page) && compound_order(page) > 1;
}

static inline void set_compound_order(struct page *page, unsigned int order)
{
    page[1].compound_order = order;
    page[1].compound_nr = 1U << order;
}

/*
 * Only to be called by the page allocator on a freshly allocated
 * page.
 */
static inline void set_page_pfmemalloc(struct page *page)
{
    page->lru.next = (void *)BIT(1);
}

static inline void clear_page_pfmemalloc(struct page *page)
{
    page->lru.next = NULL;
}

/*
 * Drop a ref, return true if the refcount fell to zero (the page has no users)
 */
static inline int put_page_testzero(struct page *page)
{
    VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);
    return page_ref_dec_and_test(page);
}

static inline pg_data_t *page_pgdat(const struct page *page)
{
    return NODE_DATA(page_to_nid(page));
}

extern atomic_long_t _totalram_pages;
static inline unsigned long totalram_pages(void)
{
    return (unsigned long)atomic_long_read(&_totalram_pages);
}

static inline struct page *virt_to_head_page(const void *x)
{
    struct page *page = virt_to_page(x);

    return compound_head(page);
}

void setup_initial_init_mm(void *start_code, void *end_code,
                           void *end_data, void *brk);

/*
 * Some inline functions in vmstat.h depend on page_zone()
 */
#include <linux/vmstat.h>

#define offset_in_page(p)       ((unsigned long)(p) & ~PAGE_MASK)
#define offset_in_thp(page, p)  ((unsigned long)(p) & (thp_size(page) - 1))
#define offset_in_folio(folio, p) ((unsigned long)(p) & (folio_size(folio) - 1))

#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
#error "NOT SUPPORT ALLOC_SPLIT_PTLOCKS!"
#else /* ALLOC_SPLIT_PTLOCKS */
static inline void ptlock_cache_init(void)
{
}

static inline bool ptlock_alloc(struct page *page)
{
    return true;
}

static inline void ptlock_free(struct page *page)
{
}

static inline spinlock_t *ptlock_ptr(struct page *page)
{
    return &page->ptl;
}
#endif /* ALLOC_SPLIT_PTLOCKS */

static inline bool ptlock_init(struct page *page)
{
    /*
     * prep_new_page() initialize page->private (and therefore page->ptl)
     * with 0. Make sure nobody took it in use in between.
     *
     * It can happen if arch try to use slab for page table allocation:
     * slab code uses page->slab_cache, which share storage with page->ptl.
     */
    VM_BUG_ON_PAGE(*(unsigned long *)&page->ptl, page);
    spin_lock_init(ptlock_ptr(page));
    return true;
}

#else /* !USE_SPLIT_PTE_PTLOCKS */
#error "NO USE_SPLIT_PTE_PTLOCKS!"
#endif /* USE_SPLIT_PTE_PTLOCKS */

#if USE_SPLIT_PMD_PTLOCKS

static struct page *pmd_to_page(pmd_t *pmd)
{
    unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
    return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
    return ptlock_ptr(pmd_to_page(pmd));
}

static inline bool pmd_ptlock_init(struct page *page)
{
    return ptlock_init(page);
}

static inline void pmd_ptlock_free(struct page *page)
{
    ptlock_free(page);
}

#else /* !USE_SPLIT_PMD_PTLOCKS */
#error "NO USE_SPLIT_PMD_PTLOCKS!"
#endif /* USE_SPLIT_PMD_PTLOCKS */

static inline bool pgtable_pte_page_ctor(struct page *page)
{
    if (!ptlock_init(page))
        return false;
    __SetPageTable(page);
    inc_lruvec_page_state(page, NR_PAGETABLE);
    return true;
}

static inline bool pgtable_pmd_page_ctor(struct page *page)
{
    if (!pmd_ptlock_init(page))
        return false;
    __SetPageTable(page);
    inc_lruvec_page_state(page, NR_PAGETABLE);
    return true;
}

static inline unsigned long get_num_physpages(void)
{
    int nid;
    unsigned long phys_pages = 0;

    for_each_online_node(nid)
        phys_pages += node_present_pages(nid);

    return phys_pages;
}

extern __printf(3, 4)
void warn_alloc(gfp_t gfp_mask, nodemask_t *nodemask, const char *fmt, ...);


int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd);
int __pte_alloc_kernel(pmd_t *pmd);

static inline void pgtable_pmd_page_dtor(struct page *page)
{
    pmd_ptlock_free(page);
    __ClearPageTable(page);
    dec_lruvec_page_state(page, NR_PAGETABLE);
}

static inline void mm_inc_nr_pmds(struct mm_struct *mm)
{
    atomic_long_add(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_pmds(struct mm_struct *mm)
{
    atomic_long_sub(PTRS_PER_PMD * sizeof(pmd_t), &mm->pgtables_bytes);
}

static inline void mm_inc_nr_ptes(struct mm_struct *mm)
{
    atomic_long_add(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_ptes(struct mm_struct *mm)
{
    atomic_long_sub(PTRS_PER_PTE * sizeof(pte_t), &mm->pgtables_bytes);
}

static inline void mm_inc_nr_puds(struct mm_struct *mm)
{
    atomic_long_add(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

static inline void mm_dec_nr_puds(struct mm_struct *mm)
{
    atomic_long_sub(PTRS_PER_PUD * sizeof(pud_t), &mm->pgtables_bytes);
}

/*
 * No scalability reason to split PUD locks yet, but follow the same pattern
 * as the PMD locks to make it easier if we decide to.  The VM should not be
 * considered ready to switch to split PUD locks yet; there may be places
 * which need to be converted from page_table_lock.
 */
static inline spinlock_t *pud_lockptr(struct mm_struct *mm, pud_t *pud)
{
    return &mm->page_table_lock;
}

static inline spinlock_t *pud_lock(struct mm_struct *mm, pud_t *pud)
{
    spinlock_t *ptl = pud_lockptr(mm, pud);

    spin_lock(ptl);
    return ptl;
}

extern bool is_vmalloc_addr(const void *x);
extern int is_vmalloc_or_module_addr(const void *x);

/*
 * vm_fault is filled by the pagefault handler and passed to the vma's
 * ->fault function. The vma's ->fault is responsible for returning a bitmask
 * of VM_FAULT_xxx flags that give details about how the fault was handled.
 *
 * MM layer fills up gfp_mask for page allocations but fault handler might
 * alter it if its implementation requires a different allocation context.
 *
 * pgoff should be used in favour of virtual_address, if possible.
 */
struct vm_fault {
    const struct {
        struct vm_area_struct *vma; /* Target VMA */
        gfp_t gfp_mask;             /* gfp mask to be used for allocations */
        pgoff_t pgoff;              /* Logical page offset based on vma */
        unsigned long address;      /* Faulting virtual address - masked */
        unsigned long real_address; /* Faulting virtual address - unmasked */
    };
    enum fault_flag flags;      /* FAULT_FLAG_xxx flags
                                 * XXX: should really be 'const' */
    pmd_t *pmd;         /* Pointer to pmd entry matching
                         * the 'address' */
    pud_t *pud;         /* Pointer to pud entry matching
                         * the 'address'
                         */
    union {
        pte_t orig_pte;     /* Value of PTE at the time of fault */
        pmd_t orig_pmd;     /* Value of PMD at the time of fault,
                             * used by PMD fault only.
                             */
    };

    struct page *cow_page;  /* Page handler may use for COW fault */
    struct page *page;      /* ->fault handlers should return a
                             * page here, unless VM_FAULT_NOPAGE
                             * is set (which is also implied by
                             * VM_FAULT_ERROR).
                             */
    /* These three entries are valid only while holding ptl lock */
    pte_t *pte;         /* Pointer to pte entry matching
                         * the 'address'. NULL if the page
                         * table hasn't been allocated.
                         */
    spinlock_t *ptl;        /* Page table lock.
                             * Protects pte page table if 'pte'
                             * is not NULL, otherwise pmd.
                             */
    pgtable_t prealloc_pte; /* Pre-allocated pte page table.
                             * vm_ops->map_pages() sets up a page
                             * table from atomic context.
                             * do_fault_around() pre-allocates
                             * page table to avoid allocation from
                             * atomic context.
                             */
};

/* page entry size for vm->huge_fault() */
enum page_entry_size {
    PE_SIZE_PTE = 0,
    PE_SIZE_PMD,
    PE_SIZE_PUD,
};

/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs.
 */
struct vm_operations_struct {
    void (*open)(struct vm_area_struct * area);
    /**
     * @close: Called when the VMA is being removed from the MM.
     * Context: User context.  May sleep.  Caller holds mmap_lock.
     */
    void (*close)(struct vm_area_struct * area);
    /* Called any time before splitting to check if it's allowed */
    int (*may_split)(struct vm_area_struct *area, unsigned long addr);
    int (*mremap)(struct vm_area_struct *area);
    /*
     * Called by mprotect() to make driver-specific permission
     * checks before mprotect() is finalised.   The VMA must not
     * be modified.  Returns 0 if eprotect() can proceed.
     */
    int (*mprotect)(struct vm_area_struct *vma, unsigned long start,
                    unsigned long end, unsigned long newflags);
    vm_fault_t (*fault)(struct vm_fault *vmf);
    vm_fault_t (*huge_fault)(struct vm_fault *vmf,
                             enum page_entry_size pe_size);
    vm_fault_t (*map_pages)(struct vm_fault *vmf,
                            pgoff_t start_pgoff, pgoff_t end_pgoff);

    unsigned long (*pagesize)(struct vm_area_struct * area);

    /* notification that a previously read-only page is about to become
     * writable, if an error is returned it will cause a SIGBUS */
    vm_fault_t (*page_mkwrite)(struct vm_fault *vmf);

    /* same as page_mkwrite when using VM_PFNMAP|VM_MIXEDMAP */
    vm_fault_t (*pfn_mkwrite)(struct vm_fault *vmf);

    /* called by access_process_vm when get_user_pages() fails, typically
     * for use by special VMAs. See also generic_access_phys() for a generic
     * implementation useful for any iomem mapping.
     */
    int (*access)(struct vm_area_struct *vma, unsigned long addr,
                  void *buf, int len, int write);

    /* Called by the /proc/PID/maps code to ask the vma whether it
     * has a special name.  Returning non-NULL will also cause this
     * vma to be dumped unconditionally. */
    const char *(*name)(struct vm_area_struct *vma);

    /*
     * Called by vm_normal_page() for special PTEs to find the
     * page for @addr.  This is useful if the default behavior
     * (using pte_page()) would not find the correct page.
     */
    struct page *(*find_special_page)(struct vm_area_struct *vma,
                                      unsigned long addr);
};

extern vm_fault_t filemap_map_pages(struct vm_fault *vmf,
                                    pgoff_t start_pgoff, pgoff_t end_pgoff);

static inline bool put_devmap_managed_page(struct page *page)
{
    return false;
}

static inline int folio_put_testzero(struct folio *folio)
{
    return put_page_testzero(&folio->page);
}

void __put_page(struct page *page);

/* 127: arbitrary random number, small enough to assemble well */
#define folio_ref_zero_or_close_to_overflow(folio) \
    ((unsigned int) folio_ref_count(folio) + 127u <= 127u)

/**
 * folio_get - Increment the reference count on a folio.
 * @folio: The folio.
 *
 * Context: May be called in any context, as long as you know that
 * you have a refcount on the folio.  If you do not already have one,
 * folio_try_get() may be the right interface for you to use.
 */
static inline void folio_get(struct folio *folio)
{
    VM_BUG_ON_FOLIO(folio_ref_zero_or_close_to_overflow(folio), folio);
    folio_ref_inc(folio);
}

/**
 * folio_put - Decrement the reference count on a folio.
 * @folio: The folio.
 *
 * If the folio's reference count reaches zero, the memory will be
 * released back to the page allocator and may be used by another
 * allocation immediately.  Do not access the memory or the struct folio
 * after calling folio_put() unless you can be sure that it wasn't the
 * last reference.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
static inline void folio_put(struct folio *folio)
{
    if (folio_put_testzero(folio))
        __put_page(&folio->page);
}

static inline void put_page(struct page *page)
{
    struct folio *folio = page_folio(page);

    /*
     * For some devmap managed pages we need to catch refcount transition
     * from 2 to 1:
     */
    if (put_devmap_managed_page(&folio->page))
        return;
    folio_put(folio);
}

static inline pg_data_t *folio_pgdat(const struct folio *folio)
{
    return page_pgdat(&folio->page);
}

/*
 * Compound pages have a destructor function.  Provide a
 * prototype for that function and accessor functions.
 * These are _only_ valid on the head of a compound page.
 */
typedef void compound_page_dtor(struct page *);

/* Keep the enum in sync with compound_page_dtors array in mm/page_alloc.c */
extern compound_page_dtor * const compound_page_dtors[NR_COMPOUND_DTORS];

/* Returns the number of pages in this potentially compound page. */
static inline unsigned long compound_nr(struct page *page)
{
    if (!PageHead(page))
        return 1;
    return page[1].compound_nr;
}

/**
 * folio_nr_pages - The number of pages in the folio.
 * @folio: The folio.
 *
 * Return: A positive power of two.
 */
static inline long folio_nr_pages(struct folio *folio)
{
    return compound_nr(&folio->page);
}

/**
 * folio_order - The allocation order of a folio.
 * @folio: The folio.
 *
 * A folio is composed of 2^order pages.  See get_order() for the definition
 * of order.
 *
 * Return: The order of the folio.
 */
static inline unsigned int folio_order(struct folio *folio)
{
    return compound_order(&folio->page);
}

/**
 * folio_put_refs - Reduce the reference count on a folio.
 * @folio: The folio.
 * @refs: The amount to subtract from the folio's reference count.
 *
 * If the folio's reference count reaches zero, the memory will be
 * released back to the page allocator and may be used by another
 * allocation immediately.  Do not access the memory or the struct folio
 * after calling folio_put_refs() unless you can be sure that these weren't
 * the last references.
 *
 * Context: May be called in process or interrupt context, but not in NMI
 * context.  May be called while holding a spinlock.
 */
static inline void folio_put_refs(struct folio *folio, int refs)
{
    if (folio_ref_sub_and_test(folio, refs))
        __put_page(&folio->page);
}

unsigned long nr_free_buffer_pages(void);

static inline void totalram_pages_inc(void)
{
    atomic_long_inc(&_totalram_pages);
}

/* Returns the number of bytes in this potentially compound page. */
static inline unsigned long page_size(struct page *page)
{
    return PAGE_SIZE << compound_order(page);
}

extern void __init pagecache_init(void);

#define nth_page(page,n)            ((page) + (n))
#define folio_page_idx(folio, p)    ((p) - &(folio)->page)

extern void truncate_inode_pages(struct address_space *, loff_t);

bool folio_mapped(struct folio *folio);

/**
 * folio_size - The number of bytes in a folio.
 * @folio: The folio.
 *
 * Context: The caller should have a reference on the folio to prevent
 * it from being split.  It is not necessary for the folio to be locked.
 * Return: The number of bytes in this folio.
 */
static inline size_t folio_size(struct folio *folio)
{
    return PAGE_SIZE << folio_order(folio);
}

static inline enum zone_type folio_zonenum(const struct folio *folio)
{
    return page_zonenum(&folio->page);
}

int generic_error_remove_page(struct address_space *mapping, struct page *page);

static inline void mm_pgtables_bytes_init(struct mm_struct *mm)
{
    atomic_long_set(&mm->pgtables_bytes, 0);
}

static inline void vma_init(struct vm_area_struct *vma, struct mm_struct *mm)
{
    static const struct vm_operations_struct dummy_vm_ops = {};

    memset(vma, 0, sizeof(*vma));
    vma->vm_mm = mm;
    vma->vm_ops = &dummy_vm_ops;
    INIT_LIST_HEAD(&vma->anon_vma_chain);
}

static inline void vma_set_anonymous(struct vm_area_struct *vma)
{
    vma->vm_ops = NULL;
}

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
    return !vma->vm_ops;
}

/*
 * Linux kernel virtual memory manager primitives.
 * The idea being to have a "virtual" mm in the same way
 * we have a virtual fs - giving a cleaner interface to the
 * mm details, and allowing different kinds of memory mappings
 * (from shared memory to executable loading to arbitrary
 * mmap() functions).
 */

struct vm_area_struct *vm_area_alloc(struct mm_struct *);
struct vm_area_struct *vm_area_dup(struct vm_area_struct *);
void vm_area_free(struct vm_area_struct *);

pgprot_t vm_get_page_prot(unsigned long vm_flags);
void vma_set_page_prot(struct vm_area_struct *vma);

extern int insert_vm_struct(struct mm_struct *, struct vm_area_struct *);
extern void __vma_link_rb(struct mm_struct *, struct vm_area_struct *,
                          struct rb_node **, struct rb_node *);
extern void unlink_file_vma(struct vm_area_struct *);
extern struct vm_area_struct *
copy_vma(struct vm_area_struct **, unsigned long addr, unsigned long len,
         pgoff_t pgoff, bool *need_rmap_locks);
extern void exit_mmap(struct mm_struct *);

extern unsigned long stack_guard_gap;

static inline unsigned long vm_start_gap(struct vm_area_struct *vma)
{
    unsigned long vm_start = vma->vm_start;

    if (vma->vm_flags & VM_GROWSDOWN) {
        vm_start -= stack_guard_gap;
        if (vm_start > vma->vm_start)
            vm_start = 0;
    }
    return vm_start;
}

static inline unsigned long vm_end_gap(struct vm_area_struct *vma)
{
    unsigned long vm_end = vma->vm_end;

    if (vma->vm_flags & VM_GROWSUP) {
        vm_end += stack_guard_gap;
        if (vm_end < vma->vm_end)
            vm_end = -PAGE_SIZE;
    }
    return vm_end;
}

#define FOLL_WRITE  0x01    /* check pte is writable */
#define FOLL_TOUCH  0x02    /* mark page accessed */
#define FOLL_GET    0x04    /* do get_page on page */
#define FOLL_DUMP   0x08    /* give error on hole if it would be zero */
#define FOLL_FORCE  0x10    /* get_user_pages read/write w/o permission */
#define FOLL_NOWAIT 0x20    /* if a disk transfer is needed, start the IO
                             * and return without waiting upon it */
#define FOLL_NOFAULT    0x80    /* do not fault in pages */
#define FOLL_HWPOISON   0x100   /* check page is hwpoisoned */
#define FOLL_NUMA       0x200   /* force NUMA hinting page fault */
#define FOLL_MIGRATION  0x400   /* wait for page to replace migration entry */
#define FOLL_TRIED      0x800   /* a retry, previous pass started an IO */
#define FOLL_REMOTE     0x2000  /* we are working on non-current tsk/mm */
#define FOLL_COW        0x4000  /* internal GUP flag */
#define FOLL_ANON       0x8000  /* don't do file mappings */
#define FOLL_LONGTERM   0x10000 /* mapping lifetime is indefinite: see below */
#define FOLL_SPLIT_PMD  0x20000 /* split huge pmd before returning */
#define FOLL_PIN        0x40000 /* pages must be released via unpin_user_page */
#define FOLL_FAST_ONLY  0x80000 /* gup_fast: prevent fall-back to slow gup */

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
    return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

void mm_trace_rss_stat(struct mm_struct *mm, int member, long count);

static inline void add_mm_counter(struct mm_struct *mm, int member, long value)
{
#if 0
    long count = atomic_long_add_return(value, &mm->rss_stat.count[member]);

    mm_trace_rss_stat(mm, member, count);
#endif
}

long get_user_pages_remote(struct mm_struct *mm,
                           unsigned long start, unsigned long nr_pages,
                           unsigned int gup_flags, struct page **pages,
                           struct vm_area_struct **vmas, int *locked);

/*
 * Architectures that support memory tagging (assigning tags to memory regions,
 * embedding these tags into addresses that point to these memory regions, and
 * checking that the memory and the pointer tags match on memory accesses)
 * redefine this macro to strip tags from pointers.
 * It's defined as noop for architectures that don't support memory tagging.
 */
#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

struct vm_area_struct *
find_extend_vma(struct mm_struct *, unsigned long addr);

static inline bool is_cow_mapping(vm_flags_t flags)
{
    return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

extern vm_fault_t
handle_mm_fault(struct vm_area_struct *vma,
                unsigned long address, unsigned int flags,
                struct pt_regs *regs);

/*
 * FOLL_PIN and FOLL_LONGTERM may be used in various combinations with each
 * other. Here is what they mean, and how to use them:
 *
 * FOLL_LONGTERM indicates that the page will be held for an indefinite time
 * period _often_ under userspace control.  This is in contrast to
 * iov_iter_get_pages(), whose usages are transient.
 *
 * FIXME: For pages which are part of a filesystem, mappings are subject to the
 * lifetime enforced by the filesystem and we need guarantees that longterm
 * users like RDMA and V4L2 only establish mappings which coordinate usage with
 * the filesystem.  Ideas for this coordination include revoking the longterm
 * pin, delaying writeback, bounce buffer page writeback, etc.  As FS DAX was
 * added after the problem with filesystems was found FS DAX VMAs are
 * specifically failed.  Filesystem pages are still subject to bugs and use of
 * FOLL_LONGTERM should be avoided on those pages.
 *
 * FIXME: Also NOTE that FOLL_LONGTERM is not supported in every GUP call.
 * Currently only get_user_pages() and get_user_pages_fast() support this flag
 * and calls to get_user_pages_[un]locked are specifically not allowed.  This
 * is due to an incompatibility with the FS DAX check and
 * FAULT_FLAG_ALLOW_RETRY.
 *
 * In the CMA case: long term pins in a CMA region would unnecessarily fragment
 * that region.  And so, CMA attempts to migrate the page before pinning, when
 * FOLL_LONGTERM is specified.
 *
 * FOLL_PIN indicates that a special kind of tracking (not just page->_refcount,
 * but an additional pin counting system) will be invoked. This is intended for
 * anything that gets a page reference and then touches page data (for example,
 * Direct IO). This lets the filesystem know that some non-file-system entity is
 * potentially changing the pages' data. In contrast to FOLL_GET (whose pages
 * are released via put_page()), FOLL_PIN pages must be released, ultimately, by
 * a call to unpin_user_page().
 *
 * FOLL_PIN is similar to FOLL_GET: both of these pin pages. They use different
 * and separate refcounting mechanisms, however, and that means that each has
 * its own acquire and release mechanisms:
 *
 *     FOLL_GET: get_user_pages*() to acquire, and put_page() to release.
 *
 *     FOLL_PIN: pin_user_pages*() to acquire, and unpin_user_pages to release.
 *
 * FOLL_PIN and FOLL_GET are mutually exclusive for a given function call.
 * (The underlying pages may experience both FOLL_GET-based and FOLL_PIN-based
 * calls applied to them, and that's perfectly OK. This is a constraint on the
 * callers, not on the pages.)
 *
 * FOLL_PIN should be set internally by the pin_user_pages*() APIs, never
 * directly by the caller. That's in order to help avoid mismatches when
 * releasing pages: get_user_pages*() pages must be released via put_page(),
 * while pin_user_pages*() pages must be released via unpin_user_page().
 *
 * Please see Documentation/core-api/pin_user_pages.rst for more information.
 */
static inline int vm_fault_to_errno(vm_fault_t vm_fault, int foll_flags)
{
    if (vm_fault & VM_FAULT_OOM)
        return -ENOMEM;
    if (vm_fault & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
        return (foll_flags & FOLL_HWPOISON) ? -EHWPOISON : -EFAULT;
    if (vm_fault & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
        return -EFAULT;
    return 0;
}

static inline p4d_t *
p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
    return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
        NULL : p4d_offset(pgd, address);
}

static inline pud_t *
pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
    return (unlikely(p4d_none(*p4d)) && __pud_alloc(mm, p4d, address)) ?
        NULL : pud_offset(p4d, address);
}

static inline pmd_t *
pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
    return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
        NULL: pmd_offset(pud, address);
}

#define pte_alloc(mm, pmd) \
    (unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd))

static inline spinlock_t *pmd_lock(struct mm_struct *mm, pmd_t *pmd)
{
    spinlock_t *ptl = pmd_lockptr(mm, pmd);
    spin_lock(ptl);
    return ptl;
}

static inline void pgtable_pte_page_dtor(struct page *page)
{
    ptlock_free(page);
    __ClearPageTable(page);
    dec_lruvec_page_state(page, NR_PAGETABLE);
}

#define pte_unmap_unlock(pte, ptl)  do {        \
    spin_unlock(ptl);               \
    pte_unmap(pte);                 \
} while (0)

extern struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *);

void anon_vma_interval_tree_insert(struct anon_vma_chain *node,
                                   struct rb_root_cached *root);
void anon_vma_interval_tree_remove(struct anon_vma_chain *node,
                                   struct rb_root_cached *root);
struct anon_vma_chain *
anon_vma_interval_tree_iter_first(struct rb_root_cached *root,
                                  unsigned long start, unsigned long last);
struct anon_vma_chain *
anon_vma_interval_tree_iter_next(struct anon_vma_chain *node,
                                 unsigned long start, unsigned long last);

static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
    return ptlock_ptr(pmd_page(*pmd));
}

#define pte_offset_map_lock(mm, pmd, address, ptlp) \
({                          \
    spinlock_t *__ptl = pte_lockptr(mm, pmd);   \
    pte_t *__pte = pte_offset_map(pmd, address);    \
    *(ptlp) = __ptl;                \
    spin_lock(__ptl);               \
    __pte;                      \
})

/**
 * thp_nr_pages - The number of regular pages in this huge page.
 * @page: The head page of a huge page.
 */
static inline int thp_nr_pages(struct page *page)
{
    VM_BUG_ON_PGFLAGS(PageTail(page), page);
    return compound_nr(page);
}

struct page *
vm_normal_page(struct vm_area_struct *vma,
               unsigned long addr, pte_t pte);

/**
 * folio_pfn - Return the Page Frame Number of a folio.
 * @folio: The folio.
 *
 * A folio may contain multiple pages.  The pages have consecutive
 * Page Frame Numbers.
 *
 * Return: The Page Frame Number of the first page in the folio.
 */
static inline unsigned long folio_pfn(struct folio *folio)
{
    return page_to_pfn(&folio->page);
}

static inline atomic_t *folio_pincount_ptr(struct folio *folio)
{
    return &folio_page(folio, 1)->compound_pincount;
}

/*
 * GUP_PIN_COUNTING_BIAS, and the associated functions that use it, overload
 * the page's refcount so that two separate items are tracked: the original page
 * reference count, and also a new count of how many pin_user_pages() calls were
 * made against the page. ("gup-pinned" is another term for the latter).
 *
 * With this scheme, pin_user_pages() becomes special: such pages are marked as
 * distinct from normal pages. As such, the unpin_user_page() call (and its
 * variants) must be used in order to release gup-pinned pages.
 *
 * Choice of value:
 *
 * By making GUP_PIN_COUNTING_BIAS a power of two, debugging of page reference
 * counts with respect to pin_user_pages() and unpin_user_page() becomes
 * simpler, due to the fact that adding an even power of two to the page
 * refcount has the effect of using only the upper N bits, for the code that
 * counts up using the bias value. This means that the lower bits are left for
 * the exclusive use of the original code that increments and decrements by one
 * (or at least, by much smaller values than the bias value).
 *
 * Of course, once the lower bits overflow into the upper bits (and this is
 * OK, because subtraction recovers the original values), then visual inspection
 * no longer suffices to directly view the separate counts. However, for normal
 * applications that don't have huge page reference counts, this won't be an
 * issue.
 *
 * Locking: the lockless algorithm described in folio_try_get_rcu()
 * provides safe operation for get_user_pages(), page_mkclean() and
 * other calls that race to set up page table entries.
 */
#define GUP_PIN_COUNTING_BIAS (1U << 10)

bool folio_mark_dirty(struct folio *folio);
bool set_page_dirty(struct page *page);
int set_page_dirty_lock(struct page *page);

/**
 * thp_order - Order of a transparent huge page.
 * @page: Head page of a transparent huge page.
 */
static inline unsigned int thp_order(struct page *page)
{
    VM_BUG_ON_PGFLAGS(PageTail(page), page);
    return compound_order(page);
}

/**
 * thp_size - Size of a transparent huge page.
 * @page: Head page of a transparent huge page.
 *
 * Return: Number of bytes in this page.
 */
static inline unsigned long thp_size(struct page *page)
{
    return PAGE_SIZE << thp_order(page);
}

extern int set_mm_exe_file(struct mm_struct *mm,
                           struct file *new_exe_file);

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
    unsigned long flags;
    unsigned long length;
    unsigned long low_limit;
    unsigned long high_limit;
    unsigned long align_mask;
    unsigned long align_offset;
};

unsigned long randomize_stack_top(unsigned long stack_top);
unsigned long randomize_page(unsigned long start, unsigned long range);

/* Generic expand stack which grows the stack according to GROWS{UP,DOWN} */
extern int expand_stack(struct vm_area_struct *vma, unsigned long address);

static inline bool vma_is_accessible(struct vm_area_struct *vma)
{
    return vma->vm_flags & VM_ACCESS_FLAGS;
}

extern unsigned long do_mmap(struct file *file, unsigned long addr,
                             unsigned long len, unsigned long prot,
                             unsigned long flags, unsigned long pgoff,
                             unsigned long *populate, struct list_head *uf);
extern int __do_munmap(struct mm_struct *, unsigned long, size_t,
                       struct list_head *uf, bool downgrade);
extern int do_munmap(struct mm_struct *, unsigned long, size_t,
                     struct list_head *uf);

extern int __mm_populate(unsigned long addr, unsigned long len,
                         int ignore_errors);
static inline void mm_populate(unsigned long addr, unsigned long len)
{
    /* Ignore errors */
    (void) __mm_populate(addr, len, 1);
}

extern int vm_munmap(unsigned long, size_t);
extern unsigned long __must_check
vm_mmap(struct file *, unsigned long,
        unsigned long, unsigned long,
        unsigned long, unsigned long);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
extern struct vm_area_struct *
find_vma(struct mm_struct * mm, unsigned long addr);

extern struct vm_area_struct *
find_vma_prev(struct mm_struct * mm,
              unsigned long addr,
              struct vm_area_struct **pprev);

/**
 * find_vma_intersection() - Look up the first VMA which intersects the interval
 * @mm: The process address space.
 * @start_addr: The inclusive start user address.
 * @end_addr: The exclusive end user address.
 *
 * Returns: The first VMA within the provided range, %NULL otherwise.  Assumes
 * start_addr < end_addr.
 */
static inline
struct vm_area_struct *find_vma_intersection(struct mm_struct *mm,
                                             unsigned long start_addr,
                                             unsigned long end_addr)
{
    struct vm_area_struct *vma = find_vma(mm, start_addr);

    if (vma && end_addr <= vma->vm_start)
        vma = NULL;
    return vma;
}

extern bool can_do_mlock(void);

static inline struct vm_area_struct *get_gate_vma(struct mm_struct *mm)
{
    return NULL;
}
static inline int in_gate_area_no_mm(unsigned long addr) { return 0; }
static inline int in_gate_area(struct mm_struct *mm, unsigned long addr)
{
    return 0;
}

void vma_interval_tree_insert(struct vm_area_struct *node,
                              struct rb_root_cached *root);

extern int __must_check
vm_brk_flags(unsigned long, unsigned long, unsigned long);

extern unsigned long
get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long,
                  unsigned long);

extern struct vm_area_struct *
vma_merge(struct mm_struct *,
          struct vm_area_struct *prev, unsigned long addr, unsigned long end,
          unsigned long vm_flags, struct anon_vma *, struct file *, pgoff_t,
          struct mempolicy *, struct vm_userfaultfd_ctx,
          struct anon_vma_name *);

#endif /* _LINUX_MM_H */
