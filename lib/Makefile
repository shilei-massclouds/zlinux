# SPDX-License-Identifier: GPL-2.0
#
# Makefile for some libs needed in the kernel.
#

# string.o implements standard library functions like memset/memcpy etc.
# Use -ffreestanding to ensure that the compiler does not try to
# "optimize" them into calls to themselves.
CFLAGS_string.o := -ffreestanding

lib-y := ctype.o string.o vsprintf.o cmdline.o siphash.o rbtree.o radix-tree.o
lib-y += kobject.o klist.o refcount.o idr.o xarray.o random32.o
obj-y += kstrtox.o percpu_counter.o
obj-y += hexdump.o percpu-refcount.o
obj-y += lockref.o dec_and_lock.o
obj-y += hweight.o bitmap.o sbitmap.o
obj-y += kasprintf.o string_helpers.o

obj-y += devres.o
obj-y += sg_pool.o

libfdt_files = fdt.o fdt_ro.o find_bit.o

$(foreach file, $(libfdt_files), \
	$(eval CFLAGS_$(file) = -I $(srctree)/scripts/dtc/libfdt))
lib-$(CONFIG_LIBFDT) += $(libfdt_files)
lib-$(CONFIG_SMP) += cpumask.o

obj-y += math/
