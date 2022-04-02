# SPDX-License-Identifier: GPL-2.0

HOSTCC = gcc
KBUILD_USERCFLAGS := -Wall -Wmissing-prototypes -Wstrict-prototypes \
	-O2 -fomit-frame-pointer -std=gnu89
KBUILD_HOSTCFLAGS := $(KBUILD_USERCFLAGS)
export HOSTCC KBUILD_HOSTCFLAGS

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

CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
AR = $(CROSS_COMPILE)ar
OBJCOPY = $(CROSS_COMPILE)objcopy
STRIP = $(CROSS_COMPILE)strip

export CROSS_COMPILE LD CC

LDFLAGS_vmlinux =
LDFLAGS_vmlinux += --build-id=sha1

# Architecture as present in compile.h
SRCARCH := $(ARCH)

export KBUILD_LDS := arch/$(SRCARCH)/kernel/vmlinux.lds

abs_objtree := $(CURDIR)

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

KBUILD_BUILTIN := 1
export KBUILD_BUILTIN

#
# (1) Entry: all
#
PHONY := all
all:

# Objects we will link into vmlinux / subdirs we need to visit
core-y := #init/ usr/

include $(srctree)/scripts/Kbuild.include

include arch/$(SRCARCH)/Makefile

core-y += #kernel/ certs/ mm/ fs/ ipc/ security/ crypto/ block/

drivers-y := #drivers/ sound/
drivers-y += #net/ virt/

libs-y := #lib/

# (2) all -> vmlinux
$(warning r: all -> vmlinux)
all: vmlinux
	$(warning e: all -> vmlinux)

# Externally visible symbols (used by link-vmlinux.sh)
KBUILD_VMLINUX_OBJS := $(head-y) $(patsubst %/,%/built-in.a, $(core-y))
KBUILD_VMLINUX_OBJS += $(addsuffix built-in.a, $(filter %/, $(libs-y)))
KBUILD_VMLINUX_OBJS += $(patsubst %/,%/built-in.a, $(drivers-y))
KBUILD_VMLINUX_OBJS += $(patsubst %/, %/lib.a, $(filter %/, $(libs-y)))

KBUILD_VMLINUX_LIBS := $(filter-out %/, $(libs-y))

export KBUILD_VMLINUX_OBJS KBUILD_VMLINUX_LIBS

vmlinux-deps := $(KBUILD_LDS) $(KBUILD_VMLINUX_OBJS) $(KBUILD_VMLINUX_LIBS)

ARCH_POSTLINK := $(wildcard $(srctree)/arch/$(SRCARCH)/Makefile.postlink)

# Final link of vmlinux with optional arch pass after final link
cmd_link-vmlinux = \
	$(CONFIG_SHELL) $< "$(LD)" "$(KBUILD_LDFLAGS)" "$(LDFLAGS_vmlinux)"; \
	$(if $(ARCH_POSTLINK), $(MAKE) -f $(ARCH_POSTLINK) $@, true)

# (3) vmlinux -> vmlinux-deps
$(warning r: vmlinux -> vmlinux-deps ($(vmlinux-deps)))
vmlinux: scripts/link-vmlinux.sh $(vmlinux-deps) FORCE
	$(warning e: vmlinux -> vmlinux-deps)
	+$(call if_changed,link-vmlinux)

# (4) vmlinux-deps -> descend
# The actual objects are generated when descending,
# make sure no implicit rule kicks in
$(warning r: vmlinux-deps descend)
$(sort $(vmlinux-deps)): descend ;
	$(warning e: vmlinux-deps($@) -> descend)

vmlinux-dirs := $(patsubst %/,%,$(filter %/, \
	$(core-y) $(core-m) $(drivers-y) $(drivers-m) \
	$(libs-y) $(libs-m)))

build-dirs := $(vmlinux-dirs)

# (5) descend -> build-dirs
# Handle descending into subdirectories listed in $(build-dirs)
# Preset locale variables to speed up the build process. Limit locale
# tweaks to this spot to avoid wrong language settings when running
# make menuconfig etc.
# Error messages still appears in the original language
$(warning r: descend -> $(build-dirs))
PHONY += descend $(build-dirs)
descend: $(build-dirs)
	$(warning e: descend -> build-dirs)

# (6) build-dirs -> prepare
$(warning r: build-dirs ($(build-dirs)) -> prepare)
$(build-dirs): prepare
	$(warning e: build-dirs ($@) -> prepare)
	$(Q)$(MAKE) $(build)=$@ need-builtin=1 need-modorder=1

# All the preparing..
PHONY += prepare archprepare

# (7) prepare -> prepare0
$(warning r: prepare -> prepare0)
prepare: prepare0

# (8) prepare0 -> archprepare
$(warning r: prepare0 -> archprepare)
prepare0: archprepare

# (9) archprepare -> scripts
$(warning r: archprepare -> scripts)
archprepare: scripts

# Additional helpers built in scripts/
PHONY += scripts

# (10) scripts -> scripts_basic
$(warning r: scripts -> scripts_basic)
scripts: scripts_basic

# Basic helpers built in scripts/basic/

# (11) scripts_basic
PHONY += scripts_basic
scripts_basic:
	$(warning e: scripts_basic)
	$(Q)$(MAKE) $(build)=scripts/basic

PHONY += FORCE
FORCE:

.PHONY: $(PHONY)
