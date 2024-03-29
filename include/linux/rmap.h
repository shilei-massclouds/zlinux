/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RMAP_H
#define _LINUX_RMAP_H
/*
 * Declarations for Reverse Mapping functions in mm/rmap.c
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rwsem.h>
#include <linux/memcontrol.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

/* Avoid racy checks */
#define PVMW_SYNC           (1 << 0)
/* Look for migration entries rather than present PTEs */
#define PVMW_MIGRATION      (1 << 1)

/*
 * The anon_vma heads a list of private "related" vmas, to scan if
 * an anonymous page pointing to this anon_vma needs to be unmapped:
 * the vmas on the list will be related by forking, or by splitting.
 *
 * Since vmas come and go as they are split and merged (particularly
 * in mprotect), the mapping field of an anonymous page cannot point
 * directly to a vma: instead it points to an anon_vma, on whose list
 * the related vmas can be easily linked or unlinked.
 *
 * After unlinking the last vma on the list, we must garbage collect
 * the anon_vma object itself: we're guaranteed no page can be
 * pointing to this anon_vma once its vma list is empty.
 */
struct anon_vma {
    struct anon_vma *root;      /* Root of this anon_vma tree */
    struct rw_semaphore rwsem;  /* W: modification, R: walking the list */
    /*
     * The refcount is taken on an anon_vma when there is no
     * guarantee that the vma of page tables will exist for
     * the duration of the operation. A caller that takes
     * the reference is responsible for clearing up the
     * anon_vma if they are the last user on release
     */
    atomic_t refcount;

    /*
     * Count of child anon_vmas and VMAs which points to this anon_vma.
     *
     * This counter is used for making decision about reusing anon_vma
     * instead of forking new one. See comments in function anon_vma_clone.
     */
    unsigned degree;

    struct anon_vma *parent;    /* Parent of this anon_vma */

    /*
     * NOTE: the LSB of the rb_root.rb_node is set by
     * mm_take_all_locks() _after_ taking the above lock. So the
     * rb_root must only be read/written after taking the above lock
     * to be sure to see a valid next pointer. The LSB bit itself
     * is serialized by a system wide lock only visible to
     * mm_take_all_locks() (mm_all_locks_mutex).
     */

    /* Interval tree of private "related" vmas */
    struct rb_root_cached rb_root;
};

/*
 * The copy-on-write semantics of fork mean that an anon_vma
 * can become associated with multiple processes. Furthermore,
 * each child process will have its own anon_vma, where new
 * pages for that process are instantiated.
 *
 * This structure allows us to find the anon_vmas associated
 * with a VMA, or the VMAs associated with an anon_vma.
 * The "same_vma" list contains the anon_vma_chains linking
 * all the anon_vmas associated with this VMA.
 * The "rb" field indexes on an interval tree the anon_vma_chains
 * which link all the VMAs associated with this anon_vma.
 */
struct anon_vma_chain {
    struct vm_area_struct *vma;
    struct anon_vma *anon_vma;
    struct list_head same_vma;  /* locked by mmap_lock & page_table_lock */
    struct rb_node rb;          /* locked by anon_vma->rwsem */
    unsigned long rb_subtree_last;
};

/*
 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one() and invalid_vma()
 * rmap_one: executed on each vma where page is mapped
 * done: for checking traversing termination condition
 * anon_lock: for getting anon_lock by optimized way rather than default
 * invalid_vma: for skipping uninterested vma
 */
struct rmap_walk_control {
    void *arg;
    /*
     * Return false if page table scanning in rmap_walk should be stopped.
     * Otherwise, return true.
     */
    bool (*rmap_one)(struct folio *folio, struct vm_area_struct *vma,
                     unsigned long addr, void *arg);
    int (*done)(struct folio *folio);
    struct anon_vma *(*anon_lock)(struct folio *folio);
    bool (*invalid_vma)(struct vm_area_struct *vma, void *arg);
};

/*
 * anon_vma helper functions.
 */
void anon_vma_init(void);   /* create anon_vma_cachep */
int  __anon_vma_prepare(struct vm_area_struct *);
void unlink_anon_vmas(struct vm_area_struct *);
int anon_vma_clone(struct vm_area_struct *, struct vm_area_struct *);
int anon_vma_fork(struct vm_area_struct *, struct vm_area_struct *);

static inline int anon_vma_prepare(struct vm_area_struct *vma)
{
    if (likely(vma->anon_vma))
        return 0;

    return __anon_vma_prepare(vma);
}

void anon_vma_init(void);        /* create anon_vma_cachep */

static inline void anon_vma_lock_write(struct anon_vma *anon_vma)
{
    down_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_write(struct anon_vma *anon_vma)
{
    up_write(&anon_vma->root->rwsem);
}

static inline void anon_vma_lock_read(struct anon_vma *anon_vma)
{
    down_read(&anon_vma->root->rwsem);
}

static inline void anon_vma_unlock_read(struct anon_vma *anon_vma)
{
    up_read(&anon_vma->root->rwsem);
}

void __put_anon_vma(struct anon_vma *anon_vma);

static inline void put_anon_vma(struct anon_vma *anon_vma)
{
    if (atomic_dec_and_test(&anon_vma->refcount))
        __put_anon_vma(anon_vma);
}

void page_add_new_anon_rmap(struct page *, struct vm_area_struct *,
                            unsigned long address, bool compound);

void page_add_file_rmap(struct page *, struct vm_area_struct *, bool compound);

static inline void anon_vma_merge(struct vm_area_struct *vma,
                                  struct vm_area_struct *next)
{
    VM_BUG_ON_VMA(vma->anon_vma != next->anon_vma, vma);
#if 0
    unlink_anon_vmas(next);
#endif
    panic("%s: END!\n", __func__);
}

void page_remove_rmap(struct page *, struct vm_area_struct *, bool compound);

/*
 * Called from mm/vmscan.c to handle paging out
 */
int folio_referenced(struct folio *, int is_locked,
                     struct mem_cgroup *memcg, unsigned long *vm_flags);

enum ttu_flags {
    TTU_SPLIT_HUGE_PMD  = 0x4,  /* split huge PMD if any */
    TTU_IGNORE_MLOCK    = 0x8,  /* ignore mlock */
    TTU_SYNC            = 0x10, /* avoid racy checks with PVMW_SYNC */
    TTU_IGNORE_HWPOISON = 0x20, /* corrupted page is recoverable */
    TTU_BATCH_FLUSH     = 0x40, /* Batch TLB flushes where possible
                     * and caller guarantees they will
                     * do a final flush if necessary */
    TTU_RMAP_LOCKED     = 0x80, /* do not grab rmap lock:
                     * caller holds it */
};

struct page_vma_mapped_walk {
    unsigned long pfn;
    unsigned long nr_pages;
    pgoff_t pgoff;
    struct vm_area_struct *vma;
    unsigned long address;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *ptl;
    unsigned int flags;
};

#define DEFINE_PAGE_VMA_WALK(name, _page, _vma, _address, _flags)   \
    struct page_vma_mapped_walk name = {                \
        .pfn = page_to_pfn(_page),              \
        .nr_pages = compound_nr(page),              \
        .pgoff = page_to_pgoff(page),               \
        .vma = _vma,                        \
        .address = _address,                    \
        .flags = _flags,                    \
    }

#define DEFINE_FOLIO_VMA_WALK(name, _folio, _vma, _address, _flags) \
    struct page_vma_mapped_walk name = {                \
        .pfn = folio_pfn(_folio),               \
        .nr_pages = folio_nr_pages(_folio),         \
        .pgoff = folio_pgoff(_folio),               \
        .vma = _vma,                        \
        .address = _address,                    \
        .flags = _flags,                    \
    }

bool page_vma_mapped_walk(struct page_vma_mapped_walk *pvmw);

static inline void page_vma_mapped_walk_done(struct page_vma_mapped_walk *pvmw)
{
    /* HugeTLB pte is set to the relevant page table entry without pte_mapped. */
    if (pvmw->pte && !is_vm_hugetlb_page(pvmw->vma))
        pte_unmap(pvmw->pte);
    if (pvmw->ptl)
        spin_unlock(pvmw->ptl);
}

void try_to_unmap(struct folio *, enum ttu_flags flags);

#endif  /* _LINUX_RMAP_H */
