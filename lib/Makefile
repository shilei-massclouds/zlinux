# SPDX-License-Identifier: GPL-2.0
#
# Makefile for some libs needed in the kernel.
#

# string.o implements standard library functions like memset/memcpy etc.
# Use -ffreestanding to ensure that the compiler does not try to
# "optimize" them into calls to themselves.
CFLAGS_string.o := -ffreestanding

lib-y := ctype.o string.o vsprintf.o cmdline.o siphash.o
lib-y += rbtree.o radix-tree.o timerqueue.o
lib-y += kobject.o klist.o refcount.o idr.o xarray.o random32.o llist.o
lib-y += dump_stack.o
obj-y += kstrtox.o percpu_counter.o irq_regs.o iov_iter.o bust_spinlocks.o
obj-y += hexdump.o percpu-refcount.o extable.o
obj-y += lockref.o dec_and_lock.o scatterlist.o
obj-y += hweight.o bitmap.o sbitmap.o bsearch.o
obj-y += kasprintf.o string_helpers.o usercopy.o

obj-y += devres.o
obj-y += sg_pool.o sort.o ratelimit.o
obj-y += strnlen_user.o strncpy_from_user.o

libfdt_files = fdt.o fdt_ro.o find_bit.o

$(foreach file, $(libfdt_files), \
	$(eval CFLAGS_$(file) = -I $(srctree)/scripts/dtc/libfdt))
lib-$(CONFIG_LIBFDT) += $(libfdt_files)
lib-$(CONFIG_SMP) += cpumask.o

obj-y += math/
