/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/sched.h>
#include <linux/thread_info.h>

#include <asm/uaccess.h>

static __always_inline void pagefault_disabled_inc(void)
{
    current->pagefault_disabled++;
}

static __always_inline void pagefault_disabled_dec(void)
{
    current->pagefault_disabled--;
}

/*
 * These routines enable/disable the pagefault handler. If disabled, it will
 * not take any locks and go straight to the fixup table.
 *
 * User access methods will not sleep when called from a pagefault_disabled()
 * environment.
 */
static inline void pagefault_disable(void)
{
    pagefault_disabled_inc();
    /*
     * make sure to have issued the store before a pagefault
     * can hit.
     */
    barrier();
}

static inline void pagefault_enable(void)
{
    /*
     * make sure to issue those last loads/stores before enabling
     * the pagefault handler again.
     */
    barrier();
    pagefault_disabled_dec();
}

/*
 * Is the pagefault handler disabled? If so, user access methods will not sleep.
 */
static inline bool pagefault_disabled(void)
{
    return current->pagefault_disabled != 0;
}

/*
 * The pagefault handler is in general disabled by pagefault_disable() or
 * when in irq context (via in_atomic()).
 *
 * This function should only be used by the fault handlers. Other users should
 * stick to pagefault_disabled().
 * Please NEVER use preempt_disable() to disable the fault handler. With
 * !CONFIG_PREEMPT_COUNT, this is like a NOP. So the handler won't be disabled.
 * in_atomic() will report different values based on !CONFIG_PREEMPT_COUNT.
 */
#define faulthandler_disabled() (pagefault_disabled() || in_atomic())

extern __must_check unsigned long
_copy_from_user(void *, const void __user *, unsigned long);

static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
    if (likely(check_copy_size(to, n, false)))
        n = _copy_from_user(to, from, n);
    return n;
}

extern __must_check unsigned long
_copy_to_user(void __user *, const void *, unsigned long);

static __always_inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
    if (likely(check_copy_size(from, n, true)))
        n = _copy_to_user(to, from, n);
    return n;
}

long strnlen_user_nofault(const void __user *unsafe_addr, long count);

#ifndef user_access_begin
#define user_access_begin(ptr,len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_copy_from_user(d,s,l,e) unsafe_op_wrap(__copy_from_user(d,s,l),e)
static inline unsigned long user_access_save(void) { return 0UL; }
static inline void user_access_restore(unsigned long flags) { }
#endif

#ifndef user_write_access_begin
#define user_write_access_begin user_access_begin
#define user_write_access_end user_access_end
#endif
#ifndef user_read_access_begin
#define user_read_access_begin user_access_begin
#define user_read_access_end user_access_end
#endif

#endif /* __LINUX_UACCESS_H__ */
