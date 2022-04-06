# This file is included by the global makefile so that you can add your
# own architecture-specific flags and dependencies. Remember to do have
# actions for "archclean" and "archdep" for cleaning up and making
# dependencies for this architecture.

OBJCOPYFLAGS := -O binary

riscv-march-$(CONFIG_ARCH_RV64I)	:= rv64ima
riscv-march-$(CONFIG_FPU)			:= $(riscv-march-y)fd
riscv-march-$(CONFIG_RISCV_ISA_C)   := $(riscv-march-y)c

KBUILD_AFLAGS += -mabi=lp64
KBUILD_AFLAGS += -march=$(riscv-march-y)

head-y := arch/riscv/kernel/head.o

core-y += arch/riscv/

libs-y += arch/riscv/lib/

# Default target when executing plain make
boot := arch/riscv/boot
KBUILD_IMAGE := $(boot)/Image.gz

BOOT_TARGETS := Image Image.gz loader loader.bin

all: $(notdir $(KBUILD_IMAGE))

$(BOOT_TARGETS): vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@
	@$(kecho) '  Kernel: $(boot)/$@ is ready'

install:
	$(Q)$(MAKE) $(build)=$(boot) $@
