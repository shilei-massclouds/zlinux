# SPDX-License-Identifier: GPL-2.0

# SHELL used by kbuild
CONFIG_SHELL := sh
KBUILD_LDFLAGS :=

# Specify these by make comand-lines originally.
# Here just set them in this makefile for convenience.
ARCH := riscv
CROSS_COMPILE := riscv64-linux-gnu-

ARCH ?= $(SUBARCH)

LD = $(CROSS_COMPILE)ld

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

export srctree

include $(srctree)/scripts/Kbuild.include

#
# (1) Entry -> all
#
PHONY := all
all:

# Objects we will link into vmlinux / subdirs we need to visit
core-y := init/ usr/
core-y += kernel/ certs/ mm/ fs/ ipc/ security/ crypto/ block/

# (2) all -> vmlinux
all: vmlinux
	@echo "###[$@] [$^]###"

vmlinux-deps := $(KBUILD_LDS) $(KBUILD_VMLINUX_OBJS) $(KBUILD_VMLINUX_LIBS)

# (3) vmlinux -> vmlinux-deps
vmlinux: scripts/link-vmlinux.sh $(vmlinux-deps) FORCE
	@echo "###[$@] [$^]###"

# (4) vmlinux-deps -> descend
# The actual objects are generated when descending,
# make sure no implicit rule kicks in
$(sort $(vmlinux-deps)): descend
	@echo "###[$@] [$^]###"

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
PHONY += descend $(build-dirs)
descend: $(build-dirs)
	@echo "###[$@] [$^]###"

# (6) build-dirs -> prepare
$(build-dirs): prepare
	@echo "###[$@] [$^]###"

# All the preparing..
PHONY += prepare archprepare

# (7) prepare -> prepare0
prepare: prepare0
	@echo "###[$@] [$^]###"

# (8) prepare0 -> archprepare
prepare0: archprepare
	@echo "###[$@] [$^]###"

# (9) archprepare -> scripts
archprepare: scripts

# Additional helpers built in scripts/
PHONY += scripts

# (10) scripts -> scripts_basic
scripts: scripts_basic
	@echo "###[$@] [$^]###"

# Basic helpers built in scripts/basic/

# (11) scripts_basic
PHONY += scripts_basic
scripts_basic:
	@echo "###[$@] [$^]###"

ARCH_POSTLINK := $(wildcard $(srctree)/arch/$(SRCARCH)/Makefile.postlink)
# Final link of vmlinux with optional arch pass after final link
#
cmd_link-vmlinux = \
	$(CONFIG_SHELL) $< "$(LD)" "$(KBUILD_LDFLAGS)" "$(LDFLAGS_vmlinux)"; \
	$(if $(ARCH_POSTLINK), $(MAKE) -f $(ARCH_POSTLINK) $@, true)

PHONY += FORCE
FORCE:

.PHONY: $(PHONY)
