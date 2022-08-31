mmu-$(CONFIG_MMU) := memory.o vmalloc.o pgtable-generic.o mmu_gather.o

obj-y := mmzone.o vmstat.o percpu.o page-writeback.o slab_common.o util.o \
	$(mmu-y)
obj-y += memblock.o list_lru.o migrate.o mempool.o mmap.o vmacache.o mlock.o
obj-y += ioremap.o shmem.o filemap.o folio-compat.o rmap.o interval_tree.o
obj-y += backing-dev.o swap.o hugetlb.o truncate.o gup.o readahead.o mm_init.o
obj-y += vmscan.o swapfile.o pagewalk.o

obj-$(CONFIG_SLAB) += slab.o workingset.o

# Give 'page_alloc' its own module-parameter namespace
page-alloc-y := page_alloc.o

obj-y += page-alloc.o
obj-y += init-mm.o swap_state.o
