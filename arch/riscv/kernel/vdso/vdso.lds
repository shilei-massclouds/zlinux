/* SPDX-License-Identifier: GPL-2.0 */
/* CONFIG_CC_VERSION_TEXT (Do not delete this comment. See help in Kconfig) */
/*
 *
 * Automatically generated file; DO NOT EDIT.
 * Linux/riscv 5.9.0-rc4 Kernel Configuration
 *
 */
/*
 * The use of "&&" / "||" is limited in certain expressions.
 * The following enable to calculate "and" / "or" with macro expansion only.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.  CONFIG_FOO=m results in "#define CONFIG_FOO_MODULE 1" in
 * autoconf.h.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.  Note that CONFIG_FOO=y results in "#define CONFIG_FOO 1" in
 * autoconf.h, while CONFIG_FOO=m results in "#define CONFIG_FOO_MODULE 1".
 */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */
/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */
/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
/*
 * By default, CONFIG_PAGE_OFFSET value corresponds to SV48 address space so
 * define the PAGE_OFFSET value for SV39.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Limited
 * Copyright (C) 2014 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */
OUTPUT_ARCH(riscv)
SECTIONS
{
    PROVIDE(_vdso_data = . - 2 * (1 << (12)));
    PROVIDE(_timens_data = _vdso_data + (1 << (12)));
    . = SIZEOF_HEADERS;
    .hash : { *(.hash) } :text
    .gnu.hash : { *(.gnu.hash) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .gnu.version : { *(.gnu.version) }
    .gnu.version_d : { *(.gnu.version_d) }
    .gnu.version_r : { *(.gnu.version_r) }
    .note : { *(.note.*) } :text :note
    .dynamic : { *(.dynamic) } :text :dynamic
    .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
    .eh_frame : { KEEP (*(.eh_frame)) } :text
    .rodata : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
    /*
     * This linker script is used both with -r and with -shared.
     * For the layouts to match, we need to skip more than enough
     * space for the dynamic symbol table, etc. If this amount is
     * insufficient, ld -shared will error; simply increase it here.
     */
    . = 0x800;
    .text : { *(.text .text.*) } :text
    .data : {
        *(.got.plt) *(.got)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
    }
}
/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
    text PT_LOAD FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
    dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
    note PT_NOTE FLAGS(4); /* PF_R */
    eh_frame_hdr PT_GNU_EH_FRAME;
}
/*
 * This controls what symbols we export from the DSO.
 */
VERSION
{
    LINUX_4.15 {
    global:
        __vdso_rt_sigreturn;
        __vdso_gettimeofday;
        __vdso_clock_gettime;
        __vdso_clock_getres;
        __vdso_getcpu;
        __vdso_flush_icache;
    local: *;
    };
}
