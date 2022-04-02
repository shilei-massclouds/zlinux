#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# link vmlinux
#
# vmlinux is linked from the objects selected by $(KBUILD_VMLINUX_OBJS) and
# $(KBUILD_VMLINUX_LIBS). Most are built-in.a files from top-level directories
# in the kernel tree, others are specified in arch/$(ARCH)/Makefile.
# $(KBUILD_VMLINUX_LIBS) are archives which are linked conditionally
# (not within --whole-archive), and do not require symbol indexes added.
#
# vmlinux
#   ^
#   |
#   +--< $(KBUILD_VMLINUX_OBJS)
#   |    +--< init/built-in.a drivers/built-in.a mm/built-in.a + more
#   |
#   +--< $(KBUILD_VMLINUX_LIBS)
#   |    +--< lib/lib.a + more
#   |
#   +-< ${kallsymso} (see description in KALLSYMS section)
#
# vmlinux version (uname -v) cannot be updated during normal
# descending-into-subdirs phase since we do not yet know if we need to
# update vmlinux.
# Therefore this step is delayed until just before final link of vmlinux.
#
# System.map is generated to document addresses of all kernel symbols

# Error out on error
set -e

# Nice output in kbuild format
# Will be supressed by "make -s"
info()
{
	if [ "${quiet}" != "silent_" ]; then
		printf "  %-7s %s\n" "${1}" "${2}"
	fi
}

# Link of vmlinux
# ${1} - output file
# ${2}, ${3}, ... - optional extra .o files
vmlinux_link()
{
	local lds="${objtree}/${KBUILD_LDS}"
	local output=${1}
	local objects

	info LD ${output}

	# skip output file argument
	shift

    objects="--whole-archive ${KBUILD_VMLINUX_OBJS} --no-whole-archive \
        --start-group ${KBUILD_VMLINUX_LIBS} --end-group ${@}"

    ${LD} ${KBUILD_LDFLAGS} ${LDFLAGS_vmlinux} \
        -o ${output} -T ${lds} ${objects}
}

vmlinux_link vmlinux "${kallsymso}" ${btf_vmlinux_bin_o}
