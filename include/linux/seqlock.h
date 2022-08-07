/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SEQLOCK_H
#define __LINUX_SEQLOCK_H

/*
 * seqcount_t / seqlock_t - a reader-writer consistency mechanism with
 * lockless readers (read-only retry loops), and no writer starvation.
 *
 * See Documentation/locking/seqlock.rst
 *
 * Copyrights:
 * - Based on x86_64 vsyscall gettimeofday: Keith Owens, Andrea Arcangeli
 * - Sequence counters with associated locks, (C) 2020 Linutronix GmbH
 */

#include <linux/compiler.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>

#include <asm/processor.h>

#define __SEQ_LOCK(expr)

/*
 * Sequence counters (seqcount_t)
 *
 * This is the raw counting mechanism, without any writer protection.
 *
 * Write side critical sections must be serialized and non-preemptible.
 *
 * If readers can be invoked from hardirq or softirq contexts,
 * interrupts or bottom halves must also be respectively disabled before
 * entering the write section.
 *
 * This mechanism can't be used if the protected data contains pointers,
 * as the writer can invalidate a pointer that a reader is following.
 *
 * If the write serialization mechanism is one of the common kernel
 * locking primitives, use a sequence counter with associated lock
 * (seqcount_LOCKNAME_t) instead.
 *
 * If it's desired to automatically handle the sequence counter writer
 * serialization and non-preemptibility requirements, use a sequential
 * lock (seqlock_t) instead.
 *
 * See Documentation/locking/seqlock.rst
 */
typedef struct seqcount {
    unsigned sequence;
} seqcount_t;

/*
 * SEQCOUNT_LOCKNAME()  - Instantiate seqcount_LOCKNAME_t and helpers
 * seqprop_LOCKNAME_*() - Property accessors for seqcount_LOCKNAME_t
 *
 * @lockname:       "LOCKNAME" part of seqcount_LOCKNAME_t
 * @locktype:       LOCKNAME canonical C data type
 * @preemptible:    preemptibility of above locktype
 * @lockmember:     argument for lockdep_assert_held()
 * @lockbase:       associated lock release function (prefix only)
 * @lock_acquire:   associated lock acquisition function (full call)
 */
#define SEQCOUNT_LOCKNAME(lockname, locktype, preemptible, lockmember, lockbase, lock_acquire) \
typedef struct seqcount_##lockname {                    \
    seqcount_t      seqcount;               \
    __SEQ_LOCK(locktype *lock);                 \
} seqcount_##lockname##_t;                      \
                                    \
static __always_inline seqcount_t *                 \
__seqprop_##lockname##_ptr(seqcount_##lockname##_t *s)          \
{                                   \
    return &s->seqcount;                        \
}                                   \
                                    \
static __always_inline unsigned                     \
__seqprop_##lockname##_sequence(const seqcount_##lockname##_t *s)   \
{                                   \
    unsigned seq = READ_ONCE(s->seqcount.sequence);         \
                                    \
    if (!IS_ENABLED(CONFIG_PREEMPT_RT))             \
        return seq;                     \
                                    \
    if (preemptible && unlikely(seq & 1)) {             \
        __SEQ_LOCK(lock_acquire);               \
        __SEQ_LOCK(lockbase##_unlock(s->lock));         \
                                    \
        /*                          \
         * Re-read the sequence counter since the (possibly \
         * preempted) writer made progress.         \
         */                         \
        seq = READ_ONCE(s->seqcount.sequence);          \
    }                               \
                                    \
    return seq;                         \
}                                   \
                                    \
static __always_inline bool                     \
__seqprop_##lockname##_preemptible(const seqcount_##lockname##_t *s)    \
{                                   \
    if (!IS_ENABLED(CONFIG_PREEMPT_RT))             \
        return preemptible;                 \
                                    \
    /* PREEMPT_RT relies on the above LOCK+UNLOCK */        \
    return false;                           \
}                                   \
                                    \
static __always_inline void                     \
__seqprop_##lockname##_assert(const seqcount_##lockname##_t *s)     \
{                                   \
    __SEQ_LOCK(lockdep_assert_held(lockmember));            \
}

/*
 * __seqprop() for seqcount_t
 */

static inline seqcount_t *__seqprop_ptr(seqcount_t *s)
{
    return s;
}

static inline unsigned __seqprop_sequence(const seqcount_t *s)
{
    return READ_ONCE(s->sequence);
}

static inline bool __seqprop_preemptible(const seqcount_t *s)
{
    return false;
}

static inline void __seqprop_assert(const seqcount_t *s)
{
}

#define __SEQ_RT    0

SEQCOUNT_LOCKNAME(raw_spinlock, raw_spinlock_t, false, s->lock,
                  raw_spin, raw_spin_lock(s->lock))
SEQCOUNT_LOCKNAME(spinlock, spinlock_t, __SEQ_RT, s->lock,
                  spin, spin_lock(s->lock))
SEQCOUNT_LOCKNAME(rwlock, rwlock_t, __SEQ_RT, s->lock,
                  read, read_lock(s->lock))
SEQCOUNT_LOCKNAME(mutex, struct mutex, true, s->lock,
                  mutex, mutex_lock(s->lock))
SEQCOUNT_LOCKNAME(ww_mutex, struct ww_mutex, true, &s->lock->base,
                  ww_mutex, ww_mutex_lock(s->lock, NULL))

#define SEQCOUNT_DEP_MAP_INIT(lockname)
#define seqcount_init(s) __seqcount_init(s, NULL, NULL)
#define seqcount_lockdep_reader_access(x)

/**
 * SEQCNT_ZERO() - static initializer for seqcount_t
 * @name: Name of the seqcount_t instance
 */
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }

/*
 * SEQCNT_LOCKNAME_ZERO - static initializer for seqcount_LOCKNAME_t
 * @name:   Name of the seqcount_LOCKNAME_t instance
 * @lock:   Pointer to the associated LOCKNAME
 */

#define SEQCOUNT_LOCKNAME_ZERO(seq_name, assoc_lock) {  \
    .seqcount        = SEQCNT_ZERO(seq_name.seqcount),  \
    __SEQ_LOCK(.lock = (assoc_lock))                    \
}

#define SEQCNT_RAW_SPINLOCK_ZERO(name, lock)    SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_SPINLOCK_ZERO(name, lock)    SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RWLOCK_ZERO(name, lock)      SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_MUTEX_ZERO(name, lock)       SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_WW_MUTEX_ZERO(name, lock)    SEQCOUNT_LOCKNAME_ZERO(name, lock)

#define __seqprop_case(s, lockname, prop)               \
    seqcount_##lockname##_t: __seqprop_##lockname##_##prop((void *)(s))

#define __seqprop(s, prop) _Generic(*(s),               \
    seqcount_t:     __seqprop_##prop((void *)(s)),      \
    __seqprop_case((s), raw_spinlock,   prop),          \
    __seqprop_case((s), spinlock,   prop),          \
    __seqprop_case((s), rwlock,     prop),          \
    __seqprop_case((s), mutex,      prop),          \
    __seqprop_case((s), ww_mutex,   prop))

#define seqprop_ptr(s)          __seqprop(s, ptr)
#define seqprop_sequence(s)     __seqprop(s, sequence)
#define seqprop_preemptible(s)  __seqprop(s, preemptible)
#define seqprop_assert(s)       __seqprop(s, assert)

static inline void do_raw_write_seqcount_begin(seqcount_t *s)
{
    s->sequence++;
    smp_wmb();
}

static inline void do_write_seqcount_begin_nested(seqcount_t *s, int subclass)
{
    do_raw_write_seqcount_begin(s);
}

/**
 * raw_write_seqcount_begin() - start a seqcount_t write section w/o lockdep
 * @s: Pointer to seqcount_t or any of the seqcount_LOCKNAME_t variants
 *
 * Context: check write_seqcount_begin()
 */
#define raw_write_seqcount_begin(s)                 \
do {                                    \
    if (seqprop_preemptible(s))                 \
        preempt_disable();                  \
                                    \
    do_raw_write_seqcount_begin(seqprop_ptr(s));            \
} while (0)

static inline void do_write_seqcount_begin(seqcount_t *s)
{
    do_write_seqcount_begin_nested(s, 0);
}

/**
 * raw_write_seqcount_end() - end a seqcount_t write section w/o lockdep
 * @s: Pointer to seqcount_t or any of the seqcount_LOCKNAME_t variants
 *
 * Context: check write_seqcount_end()
 */
#define raw_write_seqcount_end(s)                   \
do {                                    \
    do_raw_write_seqcount_end(seqprop_ptr(s));          \
                                    \
    if (seqprop_preemptible(s))                 \
        preempt_enable();                   \
} while (0)

/**
 * write_seqcount_end() - end a seqcount_t write side critical section
 * @s: Pointer to seqcount_t or any of the seqcount_LOCKNAME_t variants
 *
 * Context: Preemption will be automatically re-enabled if and only if
 * the seqcount write serialization lock is associated, and preemptible.
 */
#define write_seqcount_end(s)                       \
do {                                    \
    do_write_seqcount_end(seqprop_ptr(s));              \
                                    \
    if (seqprop_preemptible(s))                 \
        preempt_enable();                   \
} while (0)

static inline void do_raw_write_seqcount_end(seqcount_t *s)
{
    smp_wmb();
    s->sequence++;
}

static inline void do_write_seqcount_end(seqcount_t *s)
{
    do_raw_write_seqcount_end(s);
}


static inline void __seqcount_init(seqcount_t *s, const char *name,
                                   struct lock_class_key *key)
{
    /*
     * Make sure we are not reinitializing a held lock:
     */
    s->sequence = 0;
}

/*
 * seqcount_LOCKNAME_init() - runtime initializer for seqcount_LOCKNAME_t
 * @s:      Pointer to the seqcount_LOCKNAME_t instance
 * @lock:   Pointer to the associated lock
 */

#define seqcount_LOCKNAME_init(s, _lock, lockname)  \
    do {                                            \
        seqcount_##lockname##_t *____s = (s);       \
        seqcount_init(&____s->seqcount);            \
        __SEQ_LOCK(____s->lock = (_lock));          \
    } while (0)

#define seqcount_raw_spinlock_init(s, lock) \
        seqcount_LOCKNAME_init(s, lock, raw_spinlock)
#define seqcount_spinlock_init(s, lock) \
        seqcount_LOCKNAME_init(s, lock, spinlock)
#define seqcount_rwlock_init(s, lock) \
        seqcount_LOCKNAME_init(s, lock, rwlock)
#define seqcount_mutex_init(s, lock) \
        seqcount_LOCKNAME_init(s, lock, mutex)
#define seqcount_ww_mutex_init(s, lock) \
        seqcount_LOCKNAME_init(s, lock, ww_mutex)

/*
 * Sequential locks (seqlock_t)
 *
 * Sequence counters with an embedded spinlock for writer serialization
 * and non-preemptibility.
 *
 * For more info, see:
 *    - Comments on top of seqcount_t
 *    - Documentation/locking/seqlock.rst
 */
typedef struct {
    /*
     * Make sure that readers don't starve writers on PREEMPT_RT: use
     * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
     */
    seqcount_spinlock_t seqcount;
    spinlock_t lock;
} seqlock_t;

#define __SEQLOCK_UNLOCKED(lockname)    \
{                                       \
    .seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
    .lock = __SPIN_LOCK_UNLOCKED(lockname) \
}

/**
 * seqlock_init() - dynamic initializer for seqlock_t
 * @sl: Pointer to the seqlock_t instance
 */
#define seqlock_init(sl) \
do { \
    spin_lock_init(&(sl)->lock); \
    seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock); \
} while (0)

/**
 * DEFINE_SEQLOCK(sl) - Define a statically allocated seqlock_t
 * @sl: Name of the seqlock_t instance
 */
#define DEFINE_SEQLOCK(sl) \
    seqlock_t sl = __SEQLOCK_UNLOCKED(sl)

/**
 * write_seqlock() - start a seqlock_t write side critical section
 * @sl: Pointer to seqlock_t
 *
 * write_seqlock opens a write side critical section for the given
 * seqlock_t.  It also implicitly acquires the spinlock_t embedded inside
 * that sequential lock. All seqlock_t write side sections are thus
 * automatically serialized and non-preemptible.
 *
 * Context: if the seqlock_t read section, or other write side critical
 * sections, can be invoked from hardirq or softirq contexts, use the
 * _irqsave or _bh variants of this function instead.
 */
static inline void write_seqlock(seqlock_t *sl)
{
    spin_lock(&sl->lock);
    do_write_seqcount_begin(&sl->seqcount.seqcount);
}

/**
 * write_sequnlock() - end a seqlock_t write side critical section
 * @sl: Pointer to seqlock_t
 *
 * write_sequnlock closes the (serialized and non-preemptible) write side
 * critical section of given seqlock_t.
 */
static inline void write_sequnlock(seqlock_t *sl)
{
    do_write_seqcount_end(&sl->seqcount.seqcount);
    spin_unlock(&sl->lock);
}

/**
 * write_seqcount_invalidate() - invalidate in-progress seqcount_t read
 *                               side operations
 * @s: Pointer to seqcount_t or any of the seqcount_LOCKNAME_t variants
 *
 * After write_seqcount_invalidate, no seqcount_t read side operations
 * will complete successfully and see data older than this.
 */
#define write_seqcount_invalidate(s)                    \
    do_write_seqcount_invalidate(seqprop_ptr(s))

static inline void do_write_seqcount_invalidate(seqcount_t *s)
{
    smp_wmb();
    s->sequence+=2;
}

/**
 * read_seqlock_excl() - begin a seqlock_t locking reader section
 * @sl: Pointer to seqlock_t
 *
 * read_seqlock_excl opens a seqlock_t locking reader critical section.  A
 * locking reader exclusively locks out *both* other writers *and* other
 * locking readers, but it does not update the embedded sequence number.
 *
 * Locking readers act like a normal spin_lock()/spin_unlock().
 *
 * Context: if the seqlock_t write section, *or other read sections*, can
 * be invoked from hardirq or softirq contexts, use the _irqsave or _bh
 * variant of this function instead.
 *
 * The opened read section must be closed with read_sequnlock_excl().
 */
static inline void read_seqlock_excl(seqlock_t *sl)
{
    spin_lock(&sl->lock);
}

/**
 * read_sequnlock_excl() - end a seqlock_t locking reader critical section
 * @sl: Pointer to seqlock_t
 */
static inline void read_sequnlock_excl(seqlock_t *sl)
{
    spin_unlock(&sl->lock);
}

#endif /* __LINUX_SEQLOCK_H */
