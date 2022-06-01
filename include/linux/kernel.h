/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <stdarg.h>
#include <linux/limits.h>
#include <linux/linkage.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <linux/math.h>
#include <linux/minmax.h>
//#include <linux/typecheck.h>
#include <linux/printk.h>
#include <linux/build_bug.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <uapi/linux/kernel.h>

/* This cannot be an enum because some may be used in assembly source. */
#define TAINT_WARN          9

#define might_resched() do { } while (0)
#define might_sleep() do { might_resched(); } while (0)

static inline void
___might_sleep(const char *file, int line, int preempt_offset) { }

/*
 * Values used for system_state. Ordering of the states must not be changed
 * as code checks for <, <=, >, >= STATE.
 */
extern enum system_states {
    SYSTEM_BOOTING,
    SYSTEM_SCHEDULING,
    SYSTEM_FREEING_INITMEM,
    SYSTEM_RUNNING,
    SYSTEM_HALT,
    SYSTEM_POWER_OFF,
    SYSTEM_RESTART,
    SYSTEM_SUSPEND,
} system_state;

/**
 * clamp - return a value clamped to a given range with strict typechecking
 * @val: current value
 * @lo: lowest allowable value
 * @hi: highest allowable value
 *
 * This macro does strict typechecking of @lo/@hi to make sure they are of the
 * same type as @val.  See the unnecessary pointer comparisons.
 */
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y)   __careful_cmp((type)(x), (type)(y), <)

/**
 * max_t - return maximum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define max_t(type, x, y)   __careful_cmp((type)(x), (type)(y), >)

__printf(1, 2)
void panic(const char *fmt, ...) __noreturn __cold;

extern __printf(3, 4)
int snprintf(char *buf, size_t size, const char *fmt, ...);

extern __printf(2, 0)
int vsprintf(char *buf, const char *, va_list);

extern __printf(3, 0)
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

extern __printf(3, 0)
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);

extern unsigned long simple_strtoul(const char *,char **,unsigned int);
extern long simple_strtol(const char *,char **,unsigned int);
extern unsigned long long simple_strtoull(const char *,char **,unsigned int);
extern long long simple_strtoll(const char *,char **,unsigned int);

extern char *next_arg(char *args, char **param, char **val);

extern const char hex_asc[];
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

extern const char hex_asc_upper[];
#define hex_asc_upper_lo(x) hex_asc_upper[((x) & 0x0f)]
#define hex_asc_upper_hi(x) hex_asc_upper[((x) & 0xf0) >> 4]

#define _RET_IP_ (unsigned long)__builtin_return_address(0)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({  \
    void *__mptr = (void *)(ptr);           \
    BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&   \
             !__same_type(*(ptr), void),                            \
             "pointer type mismatch in container_of()");            \
    ((type *)(__mptr - offsetof(type, member))); })

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
/**
 * round_down - round down to next specified power of 2
 * @x: the value to round
 * @y: multiple to round down to (must be a power of 2)
 *
 * Rounds @x down to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding down, use rounddown() below.
 */
#define round_down(x, y) ((x) & ~__round_mask(x, y))

/*
 * panic_cpu is used for synchronizing panic() and crash_kexec() execution. It
 * holds a CPU number which is executing panic() currently. A value of
 * PANIC_CPU_INVALID means no CPU has entered panic() or crash_kexec().
 */
extern atomic_t panic_cpu;
#define PANIC_CPU_INVALID   -1

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#endif /* _LINUX_KERNEL_H */
