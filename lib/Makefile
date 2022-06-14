# SPDX-License-Identifier: GPL-2.0
#
# Makefile for some libs needed in the kernel.
#

# string.o implements standard library functions like memset/memcpy etc.
# Use -ffreestanding to ensure that the compiler does not try to
# "optimize" them into calls to themselves.
CFLAGS_string.o := -ffreestanding

lib-y := ctype.o string.o vsprintf.o cmdline.o siphash.o rbtree.o
lib-y += kobject.o refcount.o
obj-y += kstrtox.o
obj-y += hexdump.o
obj-y += hweight.o bitmap.o

libfdt_files = fdt.o fdt_ro.o find_bit.o

$(foreach file, $(libfdt_files), \
	$(eval CFLAGS_$(file) = -I $(srctree)/scripts/dtc/libfdt))
lib-$(CONFIG_LIBFDT) += $(libfdt_files)
lib-$(CONFIG_SMP) += cpumask.o

obj-y += math/
