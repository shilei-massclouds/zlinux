// SPDX-License-Identifier: GPL-2.0-only
/*
 * jump label support
 *
 * Copyright (C) 2009 Jason Baron <jbaron@redhat.com>
 * Copyright (C) 2011 Peter Zijlstra
 *
 */
//#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/err.h>
//#include <linux/static_key.h>
//#include <linux/jump_label_ratelimit.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <asm/sections.h>

struct static_key_mod {
    struct static_key_mod *next;
    struct jump_entry *entries;
    struct module *mod;
};

static inline bool static_key_linked(struct static_key *key)
{
    return key->type & JUMP_TYPE_LINKED;
}

static enum jump_label_type jump_label_type(struct jump_entry *entry)
{
    struct static_key *key = jump_entry_key(entry);
    bool enabled = static_key_enabled(key);
    bool branch = jump_entry_is_branch(entry);

    /* See the comment in linux/jump_label.h */
    return enabled ^ branch;
}

static inline
struct static_key_mod *static_key_mod(struct static_key *key)
{
    WARN_ON_ONCE(!static_key_linked(key));
    return (struct static_key_mod *)(key->type & ~JUMP_TYPE_MASK);
}

/* mutex to protect coming/going of the jump_label table */
static DEFINE_MUTEX(jump_label_mutex);

void jump_label_lock(void)
{
    mutex_lock(&jump_label_mutex);
}

void jump_label_unlock(void)
{
    mutex_unlock(&jump_label_mutex);
}

static int jump_label_cmp(const void *a, const void *b)
{
    const struct jump_entry *jea = a;
    const struct jump_entry *jeb = b;

    /*
     * Entrires are sorted by key.
     */
    if (jump_entry_key(jea) < jump_entry_key(jeb))
        return -1;

    if (jump_entry_key(jea) > jump_entry_key(jeb))
        return 1;

    /*
     * In the batching mode, entries should also be sorted by the code
     * inside the already sorted list of entries, enabling a bsearch in
     * the vector.
     */
    if (jump_entry_code(jea) < jump_entry_code(jeb))
        return -1;

    if (jump_entry_code(jea) > jump_entry_code(jeb))
        return 1;

    return 0;
}

static void jump_label_swap(void *a, void *b, int size)
{
    long delta = (unsigned long)a - (unsigned long)b;
    struct jump_entry *jea = a;
    struct jump_entry *jeb = b;
    struct jump_entry tmp = *jea;

    jea->code   = jeb->code - delta;
    jea->target = jeb->target - delta;
    jea->key    = jeb->key - delta;

    jeb->code   = tmp.code + delta;
    jeb->target = tmp.target + delta;
    jeb->key    = tmp.key + delta;
}

static void
jump_label_sort_entries(struct jump_entry *start,
                        struct jump_entry *stop)
{
    unsigned long size;
    void *swapfn = NULL;

    swapfn = jump_label_swap;

    size = (((unsigned long)stop - (unsigned long)start) /
            sizeof(struct jump_entry));
    sort(start, size, sizeof(struct jump_entry), jump_label_cmp,
         swapfn);
}

static void __jump_label_mod_update(struct static_key *key)
{
    struct static_key_mod *mod;

    for (mod = static_key_mod(key); mod; mod = mod->next) {
        panic("%s: END!\n", __func__);
    }
}

static inline
struct jump_entry *static_key_entries(struct static_key *key)
{
    WARN_ON_ONCE(key->type & JUMP_TYPE_LINKED);
    return (struct jump_entry *)(key->type & ~JUMP_TYPE_MASK);
}

static bool jump_label_can_update(struct jump_entry *entry, bool init)
{
    panic("%s: END!\n", __func__);
}

static void __jump_label_update(struct static_key *key,
                                struct jump_entry *entry,
                                struct jump_entry *stop,
                                bool init)
{
    for (; (entry < stop) && (jump_entry_key(entry) == key); entry++) {
        if (jump_label_can_update(entry, init))
            arch_jump_label_transform(entry, jump_label_type(entry));
    }
}

static void jump_label_update(struct static_key *key)
{
    struct jump_entry *stop = __stop___jump_table;
    bool init = system_state < SYSTEM_RUNNING;
    struct jump_entry *entry;
    struct module *mod;

    if (static_key_linked(key)) {
        __jump_label_mod_update(key);
        return;
    }

    preempt_disable();
    mod = __module_address((unsigned long)key);
    if (mod) {
        stop = mod->jump_entries + mod->num_jump_entries;
        init = mod->state == MODULE_STATE_COMING;
    }
    preempt_enable();
    entry = static_key_entries(key);
    /* if there are no users, entry can be NULL */
    if (entry)
        __jump_label_update(key, entry, stop, init);
}

void static_key_slow_inc_cpuslocked(struct static_key *key)
{
    int v, v1;

    STATIC_KEY_CHECK_USE(key);

    /*
     * Careful if we get concurrent static_key_slow_inc() calls;
     * later calls must wait for the first one to _finish_ the
     * jump_label_update() process.  At the same time, however,
     * the jump_label_update() call below wants to see
     * static_key_enabled(&key) for jumps to be updated properly.
     *
     * So give a special meaning to negative key->enabled: it sends
     * static_key_slow_inc() down the slow path, and it is non-zero
     * so it counts as "enabled" in jump_label_update().  Note that
     * atomic_inc_unless_negative() checks >= 0, so roll our own.
     */
    for (v = atomic_read(&key->enabled); v > 0; v = v1) {
        v1 = atomic_cmpxchg(&key->enabled, v, v + 1);
        if (likely(v1 == v))
            return;
    }

    jump_label_lock();
    if (atomic_read(&key->enabled) == 0) {
        atomic_set(&key->enabled, -1);
        jump_label_update(key);
        /*
         * Ensure that if the above cmpxchg loop observes our positive
         * value, it must also observe all the text changes.
         */
        atomic_set_release(&key->enabled, 1);
    } else {
        atomic_inc(&key->enabled);
    }
    jump_label_unlock();
}

void static_key_slow_inc(struct static_key *key)
{
    cpus_read_lock();
    static_key_slow_inc_cpuslocked(key);
    cpus_read_unlock();
}
EXPORT_SYMBOL_GPL(static_key_slow_inc);

/***
 * A 'struct static_key' uses a union such that it either points directly
 * to a table of 'struct jump_entry' or to a linked list of modules which in
 * turn point to 'struct jump_entry' tables.
 *
 * The two lower bits of the pointer are used to keep track of which pointer
 * type is in use and to store the initial branch direction, we use an access
 * function which preserves these bits.
 */
static void static_key_set_entries(struct static_key *key,
                                   struct jump_entry *entries)
{
    unsigned long type;

    WARN_ON_ONCE((unsigned long)entries & JUMP_TYPE_MASK);
    type = key->type & JUMP_TYPE_MASK;
    key->entries = entries;
    key->type |= type;
}

void static_key_enable_cpuslocked(struct static_key *key)
{
    STATIC_KEY_CHECK_USE(key);

    if (atomic_read(&key->enabled) > 0) {
        WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
        return;
    }

    jump_label_lock();
    if (atomic_read(&key->enabled) == 0) {
        atomic_set(&key->enabled, -1);
        jump_label_update(key);
        /*
         * See static_key_slow_inc().
         */
        atomic_set_release(&key->enabled, 1);
    }
    jump_label_unlock();
}
EXPORT_SYMBOL_GPL(static_key_enable_cpuslocked);

void static_key_enable(struct static_key *key)
{
    cpus_read_lock();
    static_key_enable_cpuslocked(key);
    cpus_read_unlock();
}
EXPORT_SYMBOL_GPL(static_key_enable);

void __init jump_label_init(void)
{
    struct jump_entry *iter_start = __start___jump_table;
    struct jump_entry *iter_stop = __stop___jump_table;
    struct static_key *key = NULL;
    struct jump_entry *iter;

    /*
     * Since we are initializing the static_key.enabled field with
     * with the 'raw' int values (to avoid pulling in atomic.h) in
     * jump_label.h, let's make sure that is safe. There are only two
     * cases to check since we initialize to 0 or 1.
     */
    BUILD_BUG_ON((int)ATOMIC_INIT(0) != 0);
    BUILD_BUG_ON((int)ATOMIC_INIT(1) != 1);

    if (static_key_initialized)
        return;

    cpus_read_lock();
    jump_label_lock();
    jump_label_sort_entries(iter_start, iter_stop);

    for (iter = iter_start; iter < iter_stop; iter++) {
        struct static_key *iterk;
        bool in_init;

        /* rewrite NOPs */
        if (jump_label_type(iter) == JUMP_LABEL_NOP)
            arch_jump_label_transform_static(iter, JUMP_LABEL_NOP);

        in_init = init_section_contains((void *)jump_entry_code(iter), 1);
        jump_entry_set_init(iter, in_init);

        iterk = jump_entry_key(iter);
        if (iterk == key)
            continue;

        key = iterk;
        static_key_set_entries(key, iter);
    }
    static_key_initialized = true;
    jump_label_unlock();
    cpus_read_unlock();
}
