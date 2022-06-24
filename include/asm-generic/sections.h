/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_SECTIONS_H_
#define _ASM_GENERIC_SECTIONS_H_

/* References to section boundaries */

#include <linux/compiler.h>
#include <linux/types.h>

#define dereference_function_descriptor(p) ((void *)(p))
#define dereference_kernel_function_descriptor(p) ((void *)(p))

/* An address is simply the address of the function. */
typedef struct {
    unsigned long addr;
} func_desc_t;

extern char _text[], _stext[], _etext[];
extern char _data[], _sdata[], _edata[];
extern char __bss_start[], __bss_stop[];
extern char __init_begin[], __init_end[];
extern char _sinittext[], _einittext[];

extern char __start_rodata[], __end_rodata[];

extern char _start[], _end[];
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];

/**
 * is_kernel_rodata - checks if the pointer address is located in the
 *                    .rodata section
 *
 * @addr: address to check
 *
 * Returns: true if the address is located in .rodata, false otherwise.
 */
static inline bool is_kernel_rodata(unsigned long addr)
{
    return addr >= (unsigned long)__start_rodata &&
        addr < (unsigned long)__end_rodata;
}

#endif /* _ASM_GENERIC_SECTIONS_H_ */
