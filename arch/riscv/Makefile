# This file is included by the global makefile so that you can add your
# own architecture-specific flags and dependencies. Remember to do have
# actions for "archclean" and "archdep" for cleaning up and making
# dependencies for this architecture.

OBJCOPYFLAGS := -O binary

riscv-march-$(CONFIG_ARCH_RV64I)	:= rv64ima
riscv-march-$(CONFIG_FPU)			:= $(riscv-march-y)fd
riscv-march-$(CONFIG_RISCV_ISA_C)   := $(riscv-march-y)c

KBUILD_CFLAGS += -mabi=lp64
KBUILD_CFLAGS += -march=$(subst fd,,$(riscv-march-y))
KBUILD_CFLAGS += -mno-save-restore
KBUILD_CFLAGS += -DCONFIG_PAGE_OFFSET=$(CONFIG_PAGE_OFFSET)

ifeq ($(CONFIG_CMODEL_MEDANY),y)
	KBUILD_CFLAGS += -mcmodel=medany
endif

KBUILD_AFLAGS += -mabi=lp64
KBUILD_AFLAGS += -march=$(riscv-march-y)

head-y := arch/riscv/kernel/head.o

core-y += arch/riscv/

libs-y += arch/riscv/lib/

PHONY += vdso_install
vdso_install:
	$(Q)$(MAKE) $(build)=arch/riscv/kernel/vdso $@

prepare: vdso_prepare
vdso_prepare: prepare0
	$(Q)$(MAKE) $(build)=arch/riscv/kernel/vdso include/generated/vdso-offsets.h

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
