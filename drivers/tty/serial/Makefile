# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel serial device drivers.
#

obj-$(CONFIG_SERIAL_CORE) += serial_core.o
obj-$(CONFIG_SERIAL_EARLYCON) += earlycon.o
obj-$(CONFIG_SERIAL_EARLYCON_RISCV_SBI) += earlycon-riscv-sbi.o

# Now bring in any enabled 8250/16450/16550 type drivers.
obj-y += 8250/
