# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

obj-y = fork.o panic.o params.o cpu.o kthread.o exit.o \
	pid.o nsproxy.o pid_namespace.o softirq.o stop_machine.o \
	resource.o module.o user.o cred.o smpboot.o extable.o

obj-y += signal.o sys_ni.o sys.o
obj-y += user_namespace.o ucount.o
obj-y += utsname.o task_work.o
obj-y += kmod.o workqueue.o jump_label.o

obj-y += sched/
obj-y += locking/
obj-y += printk/
obj-y += irq/
obj-y += rcu/
obj-y += dma/
obj-y += time/
obj-y += cgroup/


obj-$(CONFIG_SMP) += smp.o
