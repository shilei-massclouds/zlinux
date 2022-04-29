# SPDX-License-Identifier: GPL-2.0
#
# Kbuild for top-level directory of the kernel
# vim: ft=make

#####
# Generate bounds.h

bounds-file := include/generated/bounds.h

always-y := $(bounds-file)
targets := kernel/bounds.s

$(bounds-file): kernel/bounds.s FORCE
	$(call filechk,offsets,__LINUX_BOUNDS_H__)

#####
# Generate asm-offsets.h

offsets-file := include/generated/asm-offsets.h

always-y += $(offsets-file)
targets += arch/$(SRCARCH)/kernel/asm-offsets.s

arch/$(SRCARCH)/kernel/asm-offsets.s: $(timeconst-file) $(bounds-file)

$(offsets-file): arch/$(SRCARCH)/kernel/asm-offsets.s FORCE
	$(call filechk,offsets,__ASM_OFFSETS_H__)
