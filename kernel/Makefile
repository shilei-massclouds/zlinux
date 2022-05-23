# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y = fork.o panic.o params.o cpu.o kthread.o

obj-y += sched/
obj-y += locking/
obj-y += printk/
obj-y += rcu/
obj-y += time/

obj-$(CONFIG_SMP) += smp.o
