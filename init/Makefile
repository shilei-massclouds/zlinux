# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y	:= main.o version.o mounts.o
obj-y	+= init_task.o
obj-y	+= noinitramfs.o
obj-y	+= z_tests.o
obj-y	+= calibrate.o
obj-y   += initramfs.o

mounts-y	:= do_mounts.o
mounts-y	+= do_mounts_initrd.o

# dependencies on generated files need to be listed explicitly
$(obj)/version.o: include/generated/compile.h
