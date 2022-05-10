mmu-$(CONFIG_MMU) := memory.o

obj-y := mmzone.o percpu.o page-writeback.o $(mmu-y)
obj-y += memblock.o
obj-$(CONFIG_SLAB) += slab.o

# Give 'page_alloc' its own module-parameter namespace
page-alloc-y := page_alloc.o

obj-y += page-alloc.o
