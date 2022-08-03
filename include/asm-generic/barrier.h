/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Generic barrier definitions.
 *
 * It should be possible to use these on really simple architectures,
 * but it serves more as a starting point for new ports.
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef __ASM_GENERIC_BARRIER_H
#define __ASM_GENERIC_BARRIER_H

#ifndef __ASSEMBLY__

#include <asm/rwonce.h>

/*
 * Force strict CPU ordering. And yes, this is required on UP too when we're
 * talking to devices.
 *
 * Fall back to compiler barriers if nothing better is provided.
 */

#ifndef mb
#define mb()    barrier()
#endif

#ifndef rmb
#define rmb()   mb()
#endif

#ifndef wmb
#define wmb()   mb()
#endif

#ifndef dma_rmb
#define dma_rmb()   rmb()
#endif

#ifndef dma_wmb
#define dma_wmb()   wmb()
#endif

#ifndef smp_store_release
#define smp_store_release(p, v) __smp_store_release(p, v)
#endif

#ifndef smp_mb
#define smp_mb()    __smp_mb()
#endif

#ifndef smp_rmb
#define smp_rmb()   __smp_rmb()
#endif

#ifndef smp_wmb
#define smp_wmb()   __smp_wmb()
#endif

#ifndef smp_store_mb
#define smp_store_mb(var, value)  __smp_store_mb(var, value)
#endif

#ifndef __smp_store_mb
#define __smp_store_mb(var, value)  do { WRITE_ONCE(var, value); __smp_mb(); } while (0)
#endif

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic() __smp_mb__before_atomic()
#endif

#ifndef __smp_mb__before_atomic
#define __smp_mb__before_atomic()   __smp_mb()
#endif

#ifndef __smp_mb__after_atomic
#define __smp_mb__after_atomic()    __smp_mb()
#endif

/**
 * smp_acquire__after_ctrl_dep() - Provide ACQUIRE ordering after a control dependency
 *
 * A control dependency provides a LOAD->STORE order, the additional RMB
 * provides LOAD->LOAD order, together they provide LOAD->{LOAD,STORE} order,
 * aka. (load)-ACQUIRE.
 *
 * Architectures that do not do load speculation can have this be barrier().
 */
#ifndef smp_acquire__after_ctrl_dep
#define smp_acquire__after_ctrl_dep()   smp_rmb()
#endif

#ifndef smp_load_acquire
#define smp_load_acquire(p) __smp_load_acquire(p)
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()  do { __smp_mb__after_atomic(); } while (0)
#endif

/* Barriers for virtual machine guests when talking to an SMP host */
#define virt_mb() do { __smp_mb(); } while (0)
#define virt_rmb() do { __smp_rmb(); } while (0)
#define virt_wmb() do { __smp_wmb(); } while (0)
#define virt_store_mb(var, value) do { __smp_store_mb(var, value); } while (0)
#define virt_mb__before_atomic() do { __smp_mb__before_atomic(); } while (0)
#define virt_mb__after_atomic() do { __smp_mb__after_atomic(); } while (0)
#define virt_store_release(p, v) \
    do { kcsan_release(); __smp_store_release(p, v); } while (0)
#define virt_load_acquire(p) __smp_load_acquire(p)

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_GENERIC_BARRIER_H */
