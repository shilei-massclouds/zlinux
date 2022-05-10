# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y	:= main.o version.o
obj-y	+= init_task.o
obj-y	+= z_tests.o

# dependencies on generated files need to be listed explicitly
$(obj)/version.o: include/generated/compile.h
