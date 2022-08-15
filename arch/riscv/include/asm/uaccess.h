/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 *
 * This file was copied from include/asm-generic/uaccess.h
 */

#ifndef _ASM_RISCV_UACCESS_H
#define _ASM_RISCV_UACCESS_H

//#include <asm/asm-extable.h>
#include <asm/pgtable.h>        /* for TASK_SIZE */

/*
 * User space memory access functions
 */
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/thread_info.h>
#include <asm/byteorder.h>
//#include <asm/extable.h>
#include <asm/asm.h>
#include <asm-generic/access_ok.h>

/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define MAKE_MM_SEG(s)  ((mm_segment_t) { (s) })

#define KERNEL_DS   MAKE_MM_SEG(~0UL)
#define USER_DS     MAKE_MM_SEG(TASK_SIZE)

unsigned long __must_check
__asm_copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long __must_check
__asm_copy_from_user(void *to, const void __user *from, unsigned long n);

static inline unsigned long
raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    return __asm_copy_from_user(to, from, n);
}

static inline unsigned long
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    return __asm_copy_to_user(to, from, n);
}

extern
unsigned long __must_check __clear_user(void __user *addr, unsigned long n);

static inline
unsigned long __must_check clear_user(void __user *to, unsigned long n)
{
    might_fault();
    return access_ok(to, n) ?
        __clear_user(to, n) : n;
}

#endif /* _ASM_RISCV_UACCESS_H */
