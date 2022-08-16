/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins 2003, 2004
 */
/*
 * Lock ordering in mm:
 *
 * inode->i_rwsem   (while writing or truncating, not reading or faulting)
 *   mm->mmap_lock
 *     mapping->invalidate_lock (in filemap_fault)
 *       page->flags PG_locked (lock_page)   * (see hugetlbfs below)
 *         hugetlbfs_i_mmap_rwsem_key (in huge_pmd_share)
 *           mapping->i_mmap_rwsem
 *             hugetlb_fault_mutex (hugetlbfs specific page fault mutex)
 *             anon_vma->rwsem
 *               mm->page_table_lock or pte_lock
 *                 swap_lock (in swap_duplicate, swap_info_get)
 *                   mmlist_lock (in mmput, drain_mmlist and others)
 *                   mapping->private_lock (in block_dirty_folio)
 *                     folio_lock_memcg move_lock (in block_dirty_folio)
 *                       i_pages lock (widely used)
 *                         lruvec->lru_lock (in folio_lruvec_lock_irq)
 *                   inode->i_lock (in set_page_dirty's __mark_inode_dirty)
 *                   bdi.wb->list_lock (in set_page_dirty's __mark_inode_dirty)
 *                     sb_lock (within inode_lock in fs/fs-writeback.c)
 *                     i_pages lock (widely used, in set_page_dirty,
 *                               in arch-dependent flush_dcache_mmap_lock,
 *                               within bdi.wb->list_lock in __sync_single_inode)
 *
 * anon_vma->rwsem,mapping->i_mmap_rwsem   (memory_failure, collect_procs_anon)
 *   ->tasklist_lock
 *     pte map lock
 *
 * * hugetlbfs PageHuge() pages take locks in this order:
 *         mapping->i_mmap_rwsem
 *           hugetlb_fault_mutex (hugetlbfs specific page fault mutex)
 *             page->flags PG_locked (lock_page)
 */

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
//#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
//#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
//#include <linux/huge_mm.h>
#include <linux/backing-dev.h>
#include <linux/page_idle.h>
#include <linux/memremap.h>
//#include <linux/userfaultfd_k.h>

#include <asm/tlbflush.h>

#include "internal.h"

static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

static inline struct anon_vma *anon_vma_alloc(void)
{
    struct anon_vma *anon_vma;

    anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
    if (anon_vma) {
        atomic_set(&anon_vma->refcount, 1);
        anon_vma->degree = 1;   /* Reference for first vma */
        anon_vma->parent = anon_vma;
        /*
         * Initialise the anon_vma root to point to itself. If called
         * from fork, the root will be reset to the parents anon_vma.
         */
        anon_vma->root = anon_vma;
    }

    return anon_vma;
}

static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
    return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{
    kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
                                struct anon_vma_chain *avc,
                                struct anon_vma *anon_vma)
{
    avc->vma = vma;
    avc->anon_vma = anon_vma;
    list_add(&avc->same_vma, &vma->anon_vma_chain);
    anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}

/**
 * __anon_vma_prepare - attach an anon_vma to a memory region
 * @vma: the memory region in question
 *
 * This makes sure the memory mapping described by 'vma' has
 * an 'anon_vma' attached to it, so that we can associate the
 * anonymous pages mapped into it with that anon_vma.
 *
 * The common case will be that we already have one, which
 * is handled inline by anon_vma_prepare(). But if
 * not we either need to find an adjacent mapping that we
 * can re-use the anon_vma from (very common when the only
 * reason for splitting a vma has been mprotect()), or we
 * allocate a new one.
 *
 * Anon-vma allocations are very subtle, because we may have
 * optimistically looked up an anon_vma in folio_lock_anon_vma_read()
 * and that may actually touch the rwsem even in the newly
 * allocated vma (it depends on RCU to make sure that the
 * anon_vma isn't actually destroyed).
 *
 * As a result, we need to do proper anon_vma locking even
 * for the new allocation. At the same time, we do not want
 * to do any locking for the common case of already having
 * an anon_vma.
 *
 * This must be called with the mmap_lock held for reading.
 */
int __anon_vma_prepare(struct vm_area_struct *vma)
{
    struct mm_struct *mm = vma->vm_mm;
    struct anon_vma *anon_vma, *allocated;
    struct anon_vma_chain *avc;

    might_sleep();

    avc = anon_vma_chain_alloc(GFP_KERNEL);
    if (!avc)
        goto out_enomem;

    anon_vma = find_mergeable_anon_vma(vma);
    allocated = NULL;
    if (!anon_vma) {
        anon_vma = anon_vma_alloc();
        if (unlikely(!anon_vma))
            goto out_enomem_free_avc;
        allocated = anon_vma;
    }

    anon_vma_lock_write(anon_vma);
    /* page_table_lock to protect against threads */
    spin_lock(&mm->page_table_lock);
    if (likely(!vma->anon_vma)) {
        vma->anon_vma = anon_vma;
        anon_vma_chain_link(vma, avc, anon_vma);
        /* vma reference or self-parent link for new root */
        anon_vma->degree++;
        allocated = NULL;
        avc = NULL;
    }
    spin_unlock(&mm->page_table_lock);
    anon_vma_unlock_write(anon_vma);

    if (unlikely(allocated))
        put_anon_vma(allocated);
    if (unlikely(avc))
        anon_vma_chain_free(avc);

    return 0;

 out_enomem_free_avc:
    anon_vma_chain_free(avc);
 out_enomem:
    return -ENOMEM;
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
    panic("%s: END!\n", __func__);
}

void __put_anon_vma(struct anon_vma *anon_vma)
{
    struct anon_vma *root = anon_vma->root;

    anon_vma_free(anon_vma);
    if (root != anon_vma && atomic_dec_and_test(&root->refcount))
        anon_vma_free(root);
}

/**
 * __page_set_anon_rmap - set up new anonymous rmap
 * @page:   Page or Hugepage to add to rmap
 * @vma:    VM area to add page to.
 * @address:    User virtual address of the mapping
 * @exclusive:  the page is exclusively owned by the current process
 */
static void __page_set_anon_rmap(struct page *page,
                                 struct vm_area_struct *vma,
                                 unsigned long address,
                                 int exclusive)
{
    struct anon_vma *anon_vma = vma->anon_vma;

    BUG_ON(!anon_vma);

    if (PageAnon(page))
        return;

    /*
     * If the page isn't exclusively mapped into this vma,
     * we must use the _oldest_ possible anon_vma for the
     * page mapping!
     */
    if (!exclusive)
        anon_vma = anon_vma->root;

    /*
     * page_idle does a lockless/optimistic rmap scan on page->mapping.
     * Make sure the compiler doesn't split the stores of anon_vma and
     * the PAGE_MAPPING_ANON type identifier, otherwise the rmap code
     * could mistake the mapping for a struct address_space and crash.
     */
    anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
    WRITE_ONCE(page->mapping, (struct address_space *) anon_vma);
    page->index = linear_page_index(vma, address);
}

/**
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:   the page to add the mapping to
 * @vma:    the vm area in which the mapping is added
 * @address:    the user virtual address mapped
 * @compound:   charge the page as compound or small page
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 */
void page_add_new_anon_rmap(struct page *page,
                            struct vm_area_struct *vma,
                            unsigned long address,
                            bool compound)
{
    int nr = compound ? thp_nr_pages(page) : 1;

    VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);
    __SetPageSwapBacked(page);
    if (compound) {
        VM_BUG_ON_PAGE(!PageTransHuge(page), page);
        /* increment count (starts at -1) */
        atomic_set(compound_mapcount_ptr(page), 0);
        atomic_set(compound_pincount_ptr(page), 0);

        __mod_lruvec_page_state(page, NR_ANON_THPS, nr);
    } else {
        /* Anon THP always mapped first with PMD */
        VM_BUG_ON_PAGE(PageTransCompound(page), page);
        /* increment count (starts at -1) */
        atomic_set(&page->_mapcount, 0);
    }
    __mod_lruvec_page_state(page, NR_ANON_MAPPED, nr);
    __page_set_anon_rmap(page, vma, address, 1);
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page:   the page to add the mapping to
 * @vma:    the vm area in which the mapping is added
 * @compound:   charge the page as compound or small page
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page, struct vm_area_struct *vma,
                        bool compound)
{
    int i, nr = 0;

    panic("%s: END!\n", __func__);
}

static void anon_vma_ctor(void *data)
{
    struct anon_vma *anon_vma = data;

    init_rwsem(&anon_vma->rwsem);
    atomic_set(&anon_vma->refcount, 0);
    anon_vma->rb_root = RB_ROOT_CACHED;
}

void __init anon_vma_init(void)
{
    anon_vma_cachep =
        kmem_cache_create("anon_vma", sizeof(struct anon_vma), 0,
                          SLAB_TYPESAFE_BY_RCU|SLAB_PANIC|SLAB_ACCOUNT,
                          anon_vma_ctor);
    anon_vma_chain_cachep =
        KMEM_CACHE(anon_vma_chain, SLAB_PANIC|SLAB_ACCOUNT);
}
