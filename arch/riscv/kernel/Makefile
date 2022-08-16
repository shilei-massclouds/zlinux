# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the RISC-V Linux kernel
#

extra-y += head.o
extra-y += vmlinux.lds

obj-y   += soc.o
obj-y   += cpu.o
obj-y   += entry.o
obj-y   += irq.o
obj-y   += reset.o
obj-y   += setup.o
obj-y   += signal.o
obj-y	+= smp.o
obj-y   += smpboot.o
obj-y   += traps.o
obj-y   += cpu_ops.o
obj-y   += process.o
obj-y	+= cpu_ops_sbi.o
obj-y	+= cpu_ops_spinwait.o
obj-y   += ptrace.o
obj-y   += syscall_table.o

obj-$(CONFIG_RISCV_SBI)	+= sbi.o

clean:
