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
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
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

struct folio_referenced_arg {
    int mapcount;
    int referenced;
    unsigned long vm_flags;
    struct mem_cgroup *memcg;
};

/*
 * This is a useful helper function for locking the anon_vma root as
 * we traverse the vma->anon_vma_chain, looping over anon_vma's that
 * have the same vma.
 *
 * Such anon_vma's should have the same root, so you'd expect to see
 * just a single mutex_lock for the whole traversal.
 */
static inline struct anon_vma *
lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
    struct anon_vma *new_root = anon_vma->root;
    if (new_root != root) {
        if (WARN_ON_ONCE(root))
            up_write(&root->rwsem);
        root = new_root;
        down_write(&root->rwsem);
    }
    return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
    if (root)
        up_write(&root->rwsem);
}

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

    VM_BUG_ON_PAGE(compound && !PageTransHuge(page), page);
    if (compound && PageTransHuge(page)) {
        panic("%s: PageTransHuge!\n", __func__);
    } else {
        if (PageTransCompound(page) && page_mapping(page)) {
            VM_WARN_ON_ONCE(!PageLocked(page));
            SetPageDoubleMap(compound_head(page));
        }
        if (atomic_inc_and_test(&page->_mapcount))
            nr++;
    }
out:
    if (nr)
        __mod_lruvec_page_state(page, NR_FILE_MAPPED, nr);

    mlock_vma_page(page, vma, compound);
}

/*
 * Attach the anon_vmas from src to dst.
 * Returns 0 on success, -ENOMEM on failure.
 *
 * anon_vma_clone() is called by __vma_adjust(), __split_vma(), copy_vma() and
 * anon_vma_fork(). The first three want an exact copy of src, while the last
 * one, anon_vma_fork(), may try to reuse an existing anon_vma to prevent
 * endless growth of anon_vma. Since dst->anon_vma is set to NULL before call,
 * we can identify this case by checking (!dst->anon_vma && src->anon_vma).
 *
 * If (!dst->anon_vma && src->anon_vma) is true, this function tries to find
 * and reuse existing anon_vma which has no vmas and only one child anon_vma.
 * This prevents degradation of anon_vma hierarchy to endless linear chain in
 * case of constantly forking task. On the other hand, an anon_vma with more
 * than one child isn't reused even if there was no alive vma, thus rmap
 * walker has a good chance of avoiding scanning the whole hierarchy when it
 * searches where page is mapped.
 */
int anon_vma_clone(struct vm_area_struct *dst,
                   struct vm_area_struct *src)
{
    struct anon_vma_chain *avc, *pavc;
    struct anon_vma *root = NULL;

    list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
        struct anon_vma *anon_vma;

        avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
        if (unlikely(!avc)) {
#if 0
            unlock_anon_vma_root(root);
            root = NULL;
            avc = anon_vma_chain_alloc(GFP_KERNEL);
            if (!avc)
                goto enomem_failure;
#endif
            panic("%s: 0!\n", __func__);
        }

        anon_vma = pavc->anon_vma;
        root = lock_anon_vma_root(root, anon_vma);
        anon_vma_chain_link(dst, avc, anon_vma);

        /*
         * Reuse existing anon_vma if its degree lower than two,
         * that means it has no vma and only one anon_vma child.
         *
         * Do not chose parent anon_vma, otherwise first child
         * will always reuse it. Root anon_vma is never reused:
         * it has self-parent reference and at least one child.
         */
        if (!dst->anon_vma && src->anon_vma &&
            anon_vma != src->anon_vma && anon_vma->degree < 2)
            dst->anon_vma = anon_vma;
    }
    if (dst->anon_vma)
        dst->anon_vma->degree++;
    unlock_anon_vma_root(root);
    return 0;
}

static void page_remove_file_rmap(struct page *page, bool compound)
{
    int i, nr = 0;

    VM_BUG_ON_PAGE(compound && !PageHead(page), page);

    /* Hugepages are not counted in NR_FILE_MAPPED for now. */
    if (unlikely(PageHuge(page))) {
        /* hugetlb pages are always mapped with pmds */
        atomic_dec(compound_mapcount_ptr(page));
        return;
    }

    /* page still mapped by someone else? */
    if (compound && PageTransHuge(page)) {
        int nr_pages = thp_nr_pages(page);

        for (i = 0; i < nr_pages; i++) {
            if (atomic_add_negative(-1, &page[i]._mapcount))
                nr++;
        }
        if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
            goto out;
        if (PageSwapBacked(page))
            __mod_lruvec_page_state(page, NR_SHMEM_PMDMAPPED, -nr_pages);
        else
            __mod_lruvec_page_state(page, NR_FILE_PMDMAPPED, -nr_pages);
    } else {
        if (atomic_add_negative(-1, &page->_mapcount))
            nr++;
    }
 out:
    if (nr)
        __mod_lruvec_page_state(page, NR_FILE_MAPPED, -nr);
}

static void page_remove_anon_compound_rmap(struct page *page)
{
    panic("%s: END!\n", __func__);
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page:   page to remove mapping from
 * @vma:    the vm area from which the mapping is removed
 * @compound:   uncharge the page as compound or small page
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page, struct vm_area_struct *vma,
                      bool compound)
{
    if (!PageAnon(page)) {
        page_remove_file_rmap(page, compound);
        goto out;
    }

    if (compound) {
        page_remove_anon_compound_rmap(page);
        goto out;
    }

    /* page still mapped by someone else? */
    if (!atomic_add_negative(-1, &page->_mapcount))
        goto out;

    panic("%s: END!\n", __func__);
    /*
     * It would be tidy to reset the PageAnon mapping here,
     * but that might overwrite a racing page_add_anon_rmap
     * which increments mapcount after us but sets mapping
     * before us: so leave the reset to free_unref_page,
     * and remember that it's only reliable while mapped.
     * Leaving it set also helps swapoff to reinstate ptes
     * faster for those pages still in swapcache.
     */
 out:
    munlock_vma_page(page, vma, compound);
}

void unlink_anon_vmas(struct vm_area_struct *vma)
{
    struct anon_vma_chain *avc, *next;
    struct anon_vma *root = NULL;

    /*
     * Unlink each anon_vma chained to the VMA.  This list is ordered
     * from newest to oldest, ensuring the root anon_vma gets freed last.
     */
    list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
        struct anon_vma *anon_vma = avc->anon_vma;

        root = lock_anon_vma_root(root, anon_vma);
        anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

        /*
         * Leave empty anon_vmas on the list - we'll need
         * to free them outside the lock.
         */
        if (RB_EMPTY_ROOT(&anon_vma->rb_root.rb_root)) {
            anon_vma->parent->degree--;
            continue;
        }

        list_del(&avc->same_vma);
        anon_vma_chain_free(avc);
    }
    if (vma->anon_vma) {
        vma->anon_vma->degree--;

        /*
         * vma would still be needed after unlink, and anon_vma will be prepared
         * when handle fault.
         */
        vma->anon_vma = NULL;
    }
    unlock_anon_vma_root(root);

    /*
     * Iterate the list once more, it now only contains empty and unlinked
     * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
     * needing to write-acquire the anon_vma->root->rwsem.
     */
    list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
        struct anon_vma *anon_vma = avc->anon_vma;

        VM_WARN_ON(anon_vma->degree);
        put_anon_vma(anon_vma);

        list_del(&avc->same_vma);
        anon_vma_chain_free(avc);
    }
}

static bool folio_referenced_one(struct folio *folio,
                                 struct vm_area_struct *vma,
                                 unsigned long address, void *arg)
{
    struct folio_referenced_arg *pra = arg;
    DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
    int referenced = 0;

    while (page_vma_mapped_walk(&pvmw)) {
        address = pvmw.address;

        if ((vma->vm_flags & VM_LOCKED) &&
            (!folio_test_large(folio) || !pvmw.pte)) {
            /* Restore the mlock which got missed */
            mlock_vma_folio(folio, vma, !pvmw.pte);
            page_vma_mapped_walk_done(&pvmw);
            pra->vm_flags |= VM_LOCKED;
            return false; /* To break the loop */
        }

        if (pvmw.pte) {
            if (ptep_clear_flush_young_notify(vma, address, pvmw.pte)) {
                /*
                 * Don't treat a reference through
                 * a sequentially read mapping as such.
                 * If the folio has been used in another mapping,
                 * we will catch it; if this other mapping is
                 * already gone, the unmap path will have set
                 * the referenced flag or activated the folio.
                 */
                if (likely(!(vma->vm_flags & VM_SEQ_READ)))
                    referenced++;
            }
        } else {
            /* unexpected pmd-mapped folio? */
            WARN_ON_ONCE(1);
        }

        pra->mapcount--;
    }

    if (referenced)
        folio_clear_idle(folio);
    if (folio_test_clear_young(folio))
        referenced++;

    if (referenced) {
        pra->referenced++;
        pra->vm_flags |= vma->vm_flags & ~VM_LOCKED;
    }

    if (!pra->mapcount)
        return false; /* To break the loop */

    return true;
}

/*
 * Similar to page_get_anon_vma() except it locks the anon_vma.
 *
 * Its a little more complex as it tries to keep the fast path to a single
 * atomic op -- the trylock. If we fail the trylock, we fall back to getting a
 * reference like with page_get_anon_vma() and then block on the mutex.
 */
struct anon_vma *folio_lock_anon_vma_read(struct folio *folio)
{
    panic("%s: END!\n", __func__);
}

/*
 * rmap_walk_anon - do something to anonymous page using the object-based
 * rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the anon_vma struct it points to.
 */
static void rmap_walk_anon(struct folio *folio,
                           const struct rmap_walk_control *rwc, bool locked)
{
    panic("%s: END!\n", __func__);
}

/*
 * rmap_walk_file - do something to file page using the object-based rmap method
 * @page: the page to be handled
 * @rwc: control variable according to each walk type
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 */
static void rmap_walk_file(struct folio *folio,
                           const struct rmap_walk_control *rwc, bool locked)
{
    struct address_space *mapping = folio_mapping(folio);
    pgoff_t pgoff_start, pgoff_end;
    struct vm_area_struct *vma;

    /*
     * The page lock not only makes sure that page->mapping cannot
     * suddenly be NULLified by truncation, it makes sure that the
     * structure at mapping cannot be freed and reused yet,
     * so we can safely take mapping->i_mmap_rwsem.
     */
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

    if (!mapping)
        return;

    pgoff_start = folio_pgoff(folio);
    pgoff_end = pgoff_start + folio_nr_pages(folio) - 1;
    if (!locked)
        i_mmap_lock_read(mapping);
    vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff_start, pgoff_end) {
        unsigned long address = vma_address(&folio->page, vma);

        VM_BUG_ON_VMA(address == -EFAULT, vma);
        cond_resched();

        if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
            continue;

        if (!rwc->rmap_one(folio, vma, address, rwc->arg))
            goto done;
        if (rwc->done && rwc->done(folio))
            goto done;
    }

 done:
    if (!locked)
        i_mmap_unlock_read(mapping);
}

void rmap_walk(struct folio *folio, const struct rmap_walk_control *rwc)
{
    if (unlikely(folio_test_ksm(folio)))
        rmap_walk_ksm(folio, rwc);
    else if (folio_test_anon(folio))
        rmap_walk_anon(folio, rwc, false);
    else
        rmap_walk_file(folio, rwc, false);
}

/**
 * folio_referenced() - Test if the folio was referenced.
 * @folio: The folio to test.
 * @is_locked: Caller holds lock on the folio.
 * @memcg: target memory cgroup
 * @vm_flags: A combination of all the vma->vm_flags which referenced the folio.
 *
 * Quick test_and_clear_referenced for all mappings of a folio,
 *
 * Return: The number of mappings which referenced the folio.
 */
int folio_referenced(struct folio *folio, int is_locked,
                     struct mem_cgroup *memcg, unsigned long *vm_flags)
{
    int we_locked = 0;
    struct folio_referenced_arg pra = {
        .mapcount = folio_mapcount(folio),
        .memcg = memcg,
    };
    struct rmap_walk_control rwc = {
        .rmap_one = folio_referenced_one,
        .arg = (void *)&pra,
        .anon_lock = folio_lock_anon_vma_read,
    };

    *vm_flags = 0;
    if (!pra.mapcount)
        return 0;

    if (!folio_raw_mapping(folio))
        return 0;

    if (!is_locked && (!folio_test_anon(folio) || folio_test_ksm(folio))) {
        we_locked = folio_trylock(folio);
        if (!we_locked)
            return 1;
    }

    /*
     * If we are reclaiming on behalf of a cgroup, skip
     * counting on behalf of references from different
     * cgroups
     */
    if (memcg) {
#if 0
        rwc.invalid_vma = invalid_folio_referenced_vma;
#endif
        panic("%s: memcg!\n", __func__);
    }

    rmap_walk(folio, &rwc);
    *vm_flags = pra.vm_flags;

    if (we_locked)
        folio_unlock(folio);

    return pra.referenced;
}

/* Like rmap_walk, but caller holds relevant rmap lock */
void rmap_walk_locked(struct folio *folio, const struct rmap_walk_control *rwc)
{
    /* no ksm support for now */
    VM_BUG_ON_FOLIO(folio_test_ksm(folio), folio);
    if (folio_test_anon(folio))
        rmap_walk_anon(folio, rwc, true);
    else
        rmap_walk_file(folio, rwc, true);
}

static int page_not_mapped(struct folio *folio)
{
    return !folio_mapped(folio);
}

/*
 * Returns true if the TLB flush should be deferred to the end of a batch of
 * unmap operations to reduce IPIs.
 */
static bool should_defer_flush(struct mm_struct *mm,
                               enum ttu_flags flags)
{
    bool should_defer = false;

    if (!(flags & TTU_BATCH_FLUSH))
        return false;

    /* If remote CPUs need to be flushed then defer batch the flush */
    if (cpumask_any_but(mm_cpumask(mm), get_cpu()) < nr_cpu_ids)
        should_defer = true;
    put_cpu();

    return should_defer;
}

/*
 * @arg: enum ttu_flags will be passed to this argument
 */
static bool try_to_unmap_one(struct folio *folio,
                             struct vm_area_struct *vma,
                             unsigned long address, void *arg)
{
    struct mm_struct *mm = vma->vm_mm;
    DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
    pte_t pteval;
    struct page *subpage;
    bool ret = true;
    struct mmu_notifier_range range;
    enum ttu_flags flags = (enum ttu_flags)(long)arg;

    /*
     * When racing against e.g. zap_pte_range() on another cpu,
     * in between its ptep_get_and_clear_full() and page_remove_rmap(),
     * try_to_unmap() may return before page_mapped() has become false,
     * if page table locking is skipped: use TTU_SYNC to wait for that.
     */
    if (flags & TTU_SYNC)
        pvmw.flags = PVMW_SYNC;

    if (flags & TTU_SPLIT_HUGE_PMD) {
        //split_huge_pmd_address(vma, address, false, folio);
        panic("%s: TTU_SPLIT_HUGE_PMD!\n", __func__);
    }

    /*
     * For THP, we have to assume the worse case ie pmd for invalidation.
     * For hugetlb, it could be much worse if we need to do pud
     * invalidation in the case of pmd sharing.
     *
     * Note that the folio can not be freed in this function as call of
     * try_to_unmap() must hold a reference on the folio.
     */
    range.end = vma_address_end(&pvmw);
    mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
                            address, range.end);
    if (folio_test_hugetlb(folio)) {
        /*
         * If sharing is possible, start and end will be adjusted
         * accordingly.
         */
        //adjust_range_if_pmd_sharing_possible(vma, &range.start, &range.end);
        panic("%s: folio_test_hugetlb!\n", __func__);
    }
    mmu_notifier_invalidate_range_start(&range);

    while (page_vma_mapped_walk(&pvmw)) {
        /* Unexpected PMD-mapped THP? */
        VM_BUG_ON_FOLIO(!pvmw.pte, folio);

        /*
         * If the folio is in an mlock()d vma, we must not swap it out.
         */
        if (!(flags & TTU_IGNORE_MLOCK) &&
            (vma->vm_flags & VM_LOCKED)) {
            /* Restore the mlock which got missed */
            mlock_vma_folio(folio, vma, false);
            page_vma_mapped_walk_done(&pvmw);
            ret = false;
            break;
        }

        subpage = folio_page(folio,
                    pte_pfn(*pvmw.pte) - folio_pfn(folio));
        address = pvmw.address;

        if (folio_test_hugetlb(folio) && !folio_test_anon(folio)) {
            /*
             * To call huge_pmd_unshare, i_mmap_rwsem must be
             * held in write mode.  Caller needs to explicitly
             * do this outside rmap routines.
             */
            VM_BUG_ON(!(flags & TTU_RMAP_LOCKED));

            panic("%s: 0!\n", __func__);
        }

        /* Nuke the page table entry. */
        flush_cache_page(vma, address, pte_pfn(*pvmw.pte));
        if (should_defer_flush(mm, flags)) {
#if 0
            /*
             * We clear the PTE but do not flush so potentially
             * a remote CPU could still be writing to the folio.
             * If the entry was previously clean then the
             * architecture must guarantee that a clear->dirty
             * transition on a cached TLB entry is written through
             * and traps if the PTE is unmapped.
             */
            pteval = ptep_get_and_clear(mm, address, pvmw.pte);

            set_tlb_ubc_flush_pending(mm, pte_dirty(pteval));
#endif
            panic("%s: 1.1!\n", __func__);
        } else {
            pteval = ptep_clear_flush(vma, address, pvmw.pte);
        }

        /* Set the dirty flag on the folio now the pte is gone. */
        if (pte_dirty(pteval))
            folio_mark_dirty(folio);

        /* Update high watermark before we lower rss */
        update_hiwater_rss(mm);

        if (PageHWPoison(subpage) && !(flags & TTU_IGNORE_HWPOISON)) {
            panic("%s: 5.1!\n", __func__);
        } else if (pte_unused(pteval)) {
            panic("%s: 5.2!\n", __func__);
        } else if (folio_test_anon(folio)) {
            panic("%s: 5.3!\n", __func__);
        } else {
            /*
             * This is a locked file-backed folio,
             * so it cannot be removed from the page
             * cache and replaced by a new folio before
             * mmu_notifier_invalidate_range_end, so no
             * concurrent thread might update its page table
             * to point at a new folio while a device is
             * still using this folio.
             *
             * See Documentation/vm/mmu_notifier.rst
             */
            dec_mm_counter(mm, mm_counter_file(&folio->page));
        }

     discard:
        /*
         * No need to call mmu_notifier_invalidate_range() it has be
         * done above for all cases requiring it to happen under page
         * table lock before mmu_notifier_invalidate_range_end()
         *
         * See Documentation/vm/mmu_notifier.rst
         */
        page_remove_rmap(subpage, vma, folio_test_hugetlb(folio));
        if (vma->vm_flags & VM_LOCKED)
            mlock_page_drain_local();
        folio_put(folio);
    }

    mmu_notifier_invalidate_range_end(&range);

    return ret;
}

/**
 * try_to_unmap - Try to remove all page table mappings to a folio.
 * @folio: The folio to unmap.
 * @flags: action and flags
 *
 * Tries to remove all the page table entries which are mapping this
 * folio.  It is the caller's responsibility to check if the folio is
 * still mapped if needed (use TTU_SYNC to prevent accounting races).
 *
 * Context: Caller must hold the folio lock.
 */
void try_to_unmap(struct folio *folio, enum ttu_flags flags)
{
    struct rmap_walk_control rwc = {
        .rmap_one = try_to_unmap_one,
        .arg = (void *)flags,
        .done = page_not_mapped,
        .anon_lock = folio_lock_anon_vma_read,
    };

    if (flags & TTU_RMAP_LOCKED)
        rmap_walk_locked(folio, &rwc);
    else
        rmap_walk(folio, &rwc);
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
