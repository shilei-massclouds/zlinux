# This file is included by the global makefile so that you can add your
# own architecture-specific flags and dependencies. Remember to do have
# actions for "archclean" and "archdep" for cleaning up and making
# dependencies for this architecture.

head-y := arch/riscv/kernel/head.o

core-y += arch/riscv/

libs-y += arch/riscv/lib/

# Default target when executing plain make
boot := arch/riscv/boot
KBUILD_IMAGE := #$(boot)/Image.gz

BOOT_TARGETS := Image Image.gz loader loader.bin

all: $(notdir $(KBUILD_IMAGE))

$(BOOT_TARGETS): vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@
	@$(kecho) '  Kernel: $(boot)/$@ is ready'
