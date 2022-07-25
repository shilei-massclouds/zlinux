mmu-$(CONFIG_MMU) := memory.o vmalloc.o pgtable-generic.o

obj-y := mmzone.o vmstat.o percpu.o page-writeback.o slab_common.o util.o \
	$(mmu-y)
obj-y += memblock.o list_lru.o
obj-y += ioremap.o shmem.o filemap.o
obj-y += backing-dev.o swap.o hugetlb.o
obj-$(CONFIG_SLAB) += slab.o workingset.o

# Give 'page_alloc' its own module-parameter namespace
page-alloc-y := page_alloc.o

obj-y += page-alloc.o
obj-y += init-mm.o
