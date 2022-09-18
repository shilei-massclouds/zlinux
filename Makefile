# SPDX-License-Identifier: GPL-2.0

HOSTCC = gcc
KGZIP = gzip

KBUILD_USERCFLAGS := -Wall -Wmissing-prototypes -Wstrict-prototypes \
	-O2 -fomit-frame-pointer -std=gnu89
KBUILD_HOSTCFLAGS := $(KBUILD_USERCFLAGS)
export HOSTCC
export KGZIP
export KBUILD_HOSTCFLAGS

# Read KERNELRELEASE from include/config/kernel.release (if it exists)
KERNELRELEASE = $(shell cat include/config/kernel.release 2> /dev/null)
export KERNELRELEASE

quiet = quiet_
Q = @
export quiet Q

# SHELL used by kbuild
CONFIG_SHELL := sh
KBUILD_LDFLAGS :=

# Specify these by make comand-lines originally.
# Here just set them in this makefile for convenience.
ARCH := riscv
CROSS_COMPILE := riscv64-linux-gnu-

ARCH ?= $(SUBARCH)

# Make variables (CC, etc...)
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
AR = $(CROSS_COMPILE)ar
NM = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
STRIP = $(CROSS_COMPILE)strip

CPP	= $(CC) -E

export CROSS_COMPILE LD CC CPP AR NM OBJCOPY STRIP CONFIG_SHELL

LDFLAGS_vmlinux =
LDFLAGS_vmlinux += --build-id=sha1

# Architecture as present in compile.h
SRCARCH := $(ARCH)

export ARCH SRCARCH

export KBUILD_LDS := arch/$(SRCARCH)/kernel/vmlinux.lds

export RCS_FIND_IGNORE := \( -name SCCS -o -name BitKeeper -o -name .svn -o \
              -name CVS -o -name .pc -o -name .hg -o -name .git \) \
              -prune -o

abs_objtree := $(CURDIR)

need-config := 1

ifeq ($(abs_objtree),$(CURDIR))
# Suppress "Entering directory ..." unless we are changing the work directory.
MAKEFLAGS += --no-print-directory
else
need-sub-make := 1
endif

this-makefile := $(lastword $(MAKEFILE_LIST))
abs_srctree := $(realpath $(dir $(this-makefile)))

ifeq ($(abs_srctree),$(abs_objtree))
	# building in the source tree
	srctree := .
else
	ifeq ($(abs_srctree)/,$(dir $(abs_objtree)))
		# building in a subdirectory of the source tree
		srctree := ..
	else
		srctree := $(abs_srctree)
	endif
endif

objtree := .

export srctree objtree

ifdef need-config
include include/config/auto.conf
endif

KBUILD_BUILTIN := 1
export KBUILD_BUILTIN

# Use USERINCLUDE when you must reference the UAPI directories only.
USERINCLUDE := \
	-I$(srctree)/arch/$(SRCARCH)/include/uapi \
	-I$(objtree)/arch/$(SRCARCH)/include/generated/uapi \
	-I$(srctree)/include/uapi \
	-I$(objtree)/include/generated/uapi \
	-include $(srctree)/include/linux/kconfig.h

# Use LINUXINCLUDE when you must reference the include/ directory.
# Needed to be compatible with the O= option
LINUXINCLUDE := \
	-I$(srctree)/arch/$(SRCARCH)/include \
	-I$(objtree)/arch/$(SRCARCH)/include/generated \
	-I$(objtree)/include \
	$(USERINCLUDE)

NOSTDINC_FLAGS	:= -nostdinc \
	-isystem $(shell $(CC) -print-file-name=include)

KBUILD_AFLAGS   := -D__ASSEMBLY__ -fno-PIE
KBUILD_CFLAGS   := -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs \
	-fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE \
	-Werror=implicit-function-declaration -Werror=implicit-int \
	-Wno-format-security \
	-std=gnu89 -DDEBUG
KBUILD_CPPFLAGS := -D__KERNEL__

export NOSTDINC_FLAGS LINUXINCLUDE KBUILD_CPPFLAGS KBUILD_AFLAGS KBUILD_CFLAGS

ifdef CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE
KBUILD_CFLAGS += -O2
else ifdef CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE_O3
KBUILD_CFLAGS += -O3
else ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE
KBUILD_CFLAGS += -Os
endif

stackp-flags-y                                  := -fno-stack-protector
stackp-flags-$(CONFIG_STACKPROTECTOR)           := -fstack-protector
stackp-flags-$(CONFIG_STACKPROTECTOR_STRONG)	:= -fstack-protector-strong

KBUILD_CFLAGS += $(stackp-flags-y)

KBUILD_CFLAGS += -fno-omit-frame-pointer -fno-optimize-sibling-calls

# warn about C99 declaration after statement
KBUILD_CFLAGS += -Wdeclaration-after-statement

# Variable Length Arrays (VLAs) should not be used anywhere in the kernel
KBUILD_CFLAGS += -Wvla

# disable pointer signed / unsigned warnings in gcc 4.0
KBUILD_CFLAGS += -Wno-pointer-sign

#
# (1) Entry: all
#
PHONY := all
all:

include $(srctree)/scripts/Kbuild.include

# Objects we will link into vmlinux / subdirs we need to visit
core-y := init/ #usr/
core-y += kernel/ mm/ fs/ security/ #ipc/ crypto/
core-y += block/

drivers-y := drivers/ #sound/
drivers-y += #net/ virt/

libs-y := lib/

include arch/$(SRCARCH)/Makefile

# (2) all -> vmlinux
all: vmlinux

# Externally visible symbols (used by link-vmlinux.sh)
KBUILD_VMLINUX_OBJS := $(head-y) $(patsubst %/,%/built-in.a, $(core-y))
KBUILD_VMLINUX_OBJS += $(addsuffix built-in.a, $(filter %/, $(libs-y)))
KBUILD_VMLINUX_OBJS += $(patsubst %/,%/built-in.a, $(drivers-y))
KBUILD_VMLINUX_OBJS += $(patsubst %/, %/lib.a, $(filter %/, $(libs-y)))

KBUILD_VMLINUX_LIBS := $(filter-out %/, $(libs-y))

export KBUILD_VMLINUX_OBJS KBUILD_VMLINUX_LIBS

MODLIB  = $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)
export MODLIB

vmlinux-deps := $(KBUILD_LDS) $(KBUILD_VMLINUX_OBJS) $(KBUILD_VMLINUX_LIBS)

ARCH_POSTLINK := $(wildcard $(srctree)/arch/$(SRCARCH)/Makefile.postlink)

# Final link of vmlinux with optional arch pass after final link
cmd_link-vmlinux = \
	$(CONFIG_SHELL) $< "$(LD)" "$(KBUILD_LDFLAGS)" "$(LDFLAGS_vmlinux)"; \
	$(if $(ARCH_POSTLINK), $(MAKE) -f $(ARCH_POSTLINK) $@, true)

# (3) vmlinux -> vmlinux-deps
vmlinux: scripts/link-vmlinux.sh $(vmlinux-deps) FORCE
	+$(call if_changed,link-vmlinux)

# (4) vmlinux-deps -> descend
# The actual objects are generated when descending,
# make sure no implicit rule kicks in
$(sort $(vmlinux-deps)): descend ;

vmlinux-dirs := $(patsubst %/,%,$(filter %/, \
	$(core-y) $(core-m) $(drivers-y) $(drivers-m) \
	$(libs-y) $(libs-m)))

vmlinux-alldirs := $(sort $(vmlinux-dirs))

build-dirs := $(vmlinux-dirs)
clean-dirs := $(vmlinux-alldirs)

# (5) descend -> build-dirs
# Handle descending into subdirectories listed in $(build-dirs)
# Preset locale variables to speed up the build process. Limit locale
# tweaks to this spot to avoid wrong language settings when running
# make menuconfig etc.
# Error messages still appears in the original language
PHONY += descend $(build-dirs)
descend: $(build-dirs)

# (6) build-dirs -> prepare
$(build-dirs): prepare
	$(Q)$(MAKE) $(build)=$@ need-builtin=1 need-modorder=1

# All the preparing..
PHONY += prepare archprepare

# (7) prepare -> prepare0
prepare: prepare0

# (8) prepare0 -> archprepare
prepare0: archprepare
	$(Q)$(MAKE) $(build)=.

# (9) archprepare -> scripts
archprepare: scripts

# Additional helpers built in scripts/
PHONY += scripts

# (10) scripts -> scripts_basic
scripts: scripts_basic

# Basic helpers built in scripts/basic/

# (11) scripts_basic
PHONY += scripts_basic
scripts_basic:
	$(Q)$(MAKE) $(build)=scripts/basic

# INSTALL_PATH specifies where to place the updated kernel and
# system map images.
# Default is /boot, but you can set it to other values.
export INSTALL_PATH ?= $(objtree)/output

# Directories & files removed with 'make clean'
CLEAN_FILES += include/ksym vmlinux.symvers \
			   modules.builtin modules.builtin.modinfo modules.nsdeps

PHONY += clean

# clean - Delete most, but leave enough to build external modules
clean: rm-files := $(CLEAN_FILES)

PHONY += archclean vmlinuxclean

vmlinuxclean:
	$(Q)$(CONFIG_SHELL) $(srctree)/scripts/link-vmlinux.sh clean
	$(Q)$(if $(ARCH_POSTLINK), $(MAKE) -f $(ARCH_POSTLINK) clean)

clean: archclean vmlinuxclean

clean-dirs := $(addprefix _clean_, $(clean-dirs))
PHONY += $(clean-dirs) clean
$(clean-dirs):
	$(Q)$(MAKE) $(clean)=$(patsubst _clean_%,%,$@)

quiet_cmd_rmfiles = $(if $(wildcard $(rm-files)),CLEAN $(wildcard $(rm-files)))
cmd_rmfiles = rm -rf $(rm-files)

clean: $(clean-dirs)
	$(call cmd,rmfiles)
	@find . $(RCS_FIND_IGNORE) \
		\( -name '*.[aios]' -o -name '*.ko' -o -name '.*.cmd' \
		-o -name '*.ko.*' \
		-o -name '*.dtb' -o -name '*.dtb.S' -o -name '*.dt.yaml' \
		-o -name '*.dwo' -o -name '*.lst' \
		-o -name '*.su' -o -name '*.mod' \
		-o -name '.*.d' -o -name '.*.tmp' -o -name '*.mod.c' \
		-o -name '*.lex.c' -o -name '*.tab.[ch]' \
		-o -name '*.asn1.[ch]' \
		-o -name '*.symtypes' -o -name 'modules.order' \
		-o -name '.tmp_*.o.*' \
		-o -name '*.c.[012]*.*' \
		-o -name '*.ll' \
		-o -name '*.gcno' \) -type f -print | xargs rm -f

PHONY += FORCE
FORCE:

.PHONY: $(PHONY)
