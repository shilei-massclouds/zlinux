# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux kernel device drivers.
#

obj-y               += irqchip/
obj-y               += base/ block/
# tty/ comes before char/ so that the VT console is the boot-time
# default.
obj-y               += tty/
obj-y               += char/
obj-y               += pci/
obj-y               += virtio/
# iommu/ comes before gpu as gpu are using iommu controllers
obj-y               += iommu/
obj-$(CONFIG_OF)	+= of/
obj-y               += clk/
obj-y               += clocksource/
obj-y				+= cpuidle/
obj-y				+= gpio/
