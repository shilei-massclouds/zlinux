# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y = fork.o panic.o params.o cpu.o kthread.o exit.o \
	pid.o nsproxy.o pid_namespace.o softirq.o \
	resource.o module.o user.o cred.o smpboot.o

obj-y += user_namespace.o
obj-y += kmod.o

obj-y += sched/
obj-y += locking/
obj-y += printk/
obj-y += irq/
obj-y += rcu/
obj-y += dma/
obj-y += time/

obj-$(CONFIG_SMP) += smp.o
