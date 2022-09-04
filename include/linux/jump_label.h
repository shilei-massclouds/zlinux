/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JUMP_LABEL_H
#define _LINUX_JUMP_LABEL_H

#include <asm/jump_label.h>

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/bug.h>

#define JUMP_TYPE_FALSE     0UL
#define JUMP_TYPE_TRUE      1UL
#define JUMP_TYPE_LINKED    2UL
#define JUMP_TYPE_MASK      3UL

extern bool static_key_initialized;

enum jump_label_type {
    JUMP_LABEL_NOP = 0,
    JUMP_LABEL_JMP,
};

struct jump_entry {
    s32 code;
    s32 target;
    long key;   // key may be far away from the core kernel under KASLR
};

static inline bool jump_entry_is_branch(const struct jump_entry *entry)
{
    return (unsigned long)entry->key & 1UL;
}

static inline bool jump_entry_is_init(const struct jump_entry *entry)
{
    return (unsigned long)entry->key & 2UL;
}

static inline
unsigned long jump_entry_code(const struct jump_entry *entry)
{
    return (unsigned long)&entry->code + entry->code;
}

static inline
unsigned long jump_entry_target(const struct jump_entry *entry)
{
    return (unsigned long)&entry->target + entry->target;
}

static inline
struct static_key *jump_entry_key(const struct jump_entry *entry)
{
    long offset = entry->key & ~3L;

    return (struct static_key *)((unsigned long)&entry->key + offset);
}

#define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,           \
                    "%s(): static key '%pS' used before call to jump_label_init()", \
                    __func__, (key))

struct static_key {
    atomic_t enabled;
/*
 * Note:
 *   To make anonymous unions work with old compilers, the static
 *   initialization of them requires brackets. This creates a dependency
 *   on the order of the struct with the initializers. If any fields
 *   are added, STATIC_KEY_INIT_TRUE and STATIC_KEY_INIT_FALSE may need
 *   to be modified.
 *
 * bit 0 => 1 if key is initially true
 *      0 if initially false
 * bit 1 => 1 if points to struct static_key_mod
 *      0 if points to struct jump_entry
 */
    union {
        unsigned long type;
        struct jump_entry *entries;
        struct static_key_mod *next;
    };
};

/*
 * Two type wrappers around static_key, such that we can use compile time
 * type differentiation to emit the right code.
 *
 * All the below code is macros in order to play type games.
 */

struct static_key_true {
    struct static_key key;
};

struct static_key_false {
    struct static_key key;
};

extern void static_key_slow_inc(struct static_key *key);
extern void static_key_slow_dec(struct static_key *key);

#define STATIC_KEY_INIT_TRUE    { .enabled = ATOMIC_INIT(1) }
#define STATIC_KEY_INIT_FALSE   { .enabled = ATOMIC_INIT(0) }

#define STATIC_KEY_TRUE_INIT  \
    (struct static_key_true) { .key = STATIC_KEY_INIT_TRUE,  }

#define STATIC_KEY_FALSE_INIT \
    (struct static_key_false){ .key = STATIC_KEY_INIT_FALSE, }

#define DECLARE_STATIC_KEY_TRUE(name) \
    extern struct static_key_true name

#define DECLARE_STATIC_KEY_FALSE(name) \
    extern struct static_key_false name

#define _DECLARE_STATIC_KEY_1(name) DECLARE_STATIC_KEY_TRUE(name)
#define _DECLARE_STATIC_KEY_0(name) DECLARE_STATIC_KEY_FALSE(name)

#define DECLARE_STATIC_KEY_MAYBE(cfg, name) \
    __PASTE(_DECLARE_STATIC_KEY_, IS_ENABLED(cfg))(name)

#define DEFINE_STATIC_KEY_TRUE(name)    \
    struct static_key_true name = STATIC_KEY_TRUE_INIT

#define DEFINE_STATIC_KEY_FALSE(name)   \
    struct static_key_false name = STATIC_KEY_FALSE_INIT

#define _DEFINE_STATIC_KEY_1(name)  DEFINE_STATIC_KEY_TRUE(name)
#define _DEFINE_STATIC_KEY_0(name)  DEFINE_STATIC_KEY_FALSE(name)
#define DEFINE_STATIC_KEY_MAYBE(cfg, name) \
    __PASTE(_DEFINE_STATIC_KEY_, IS_ENABLED(cfg))(name)

extern bool ____wrong_branch_error(void);

static inline int static_key_count(struct static_key *key)
{
    return atomic_read(&key->enabled);
}

#define static_key_enabled(x)                           \
({                                      \
    if (!__builtin_types_compatible_p(typeof(*x), struct static_key) && \
        !__builtin_types_compatible_p(typeof(*x), struct static_key_true) &&\
        !__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
        ____wrong_branch_error();                   \
    static_key_count((struct static_key *)x) > 0;               \
})

#define static_branch_likely(x) \
    likely_notrace(static_key_enabled(&(x)->key))

#define static_branch_unlikely(x) \
    unlikely_notrace(static_key_enabled(&(x)->key))

#define static_branch_maybe(config, x) \
    (IS_ENABLED(config) ? static_branch_likely(x) : static_branch_unlikely(x))

#define static_branch_maybe(config, x)                  \
    (IS_ENABLED(config) ? static_branch_likely(x)           \
                : static_branch_unlikely(x))

/*
 * Advanced usage; refcount, branch is enabled when: count != 0
 */

#define static_branch_inc(x)        static_key_slow_inc(&(x)->key)
#define static_branch_dec(x)        static_key_slow_dec(&(x)->key)
#define static_branch_inc_cpuslocked(x) static_key_slow_inc_cpuslocked(&(x)->key)
#define static_branch_dec_cpuslocked(x) static_key_slow_dec_cpuslocked(&(x)->key)

/*
 * Normal usage; boolean enable/disable.
 */

#define static_branch_enable(x)         static_key_enable(&(x)->key)
#define static_branch_disable(x)        static_key_disable(&(x)->key)
#define static_branch_enable_cpuslocked(x)  static_key_enable_cpuslocked(&(x)->key)
#define static_branch_disable_cpuslocked(x) static_key_disable_cpuslocked(&(x)->key)

extern void static_key_enable(struct static_key *key);
extern void static_key_disable(struct static_key *key);

extern void jump_label_init(void);

extern struct jump_entry __start___jump_table[];
extern struct jump_entry __stop___jump_table[];

extern void arch_jump_label_transform(struct jump_entry *entry,
                                      enum jump_label_type type);

static __always_inline bool static_key_false(struct static_key *key)
{
    return arch_static_branch(key, false);
}

static __always_inline bool static_key_true(struct static_key *key)
{
    return !arch_static_branch(key, true);
}

extern void
arch_jump_label_transform_static(struct jump_entry *entry,
                                 enum jump_label_type type);
extern bool
arch_jump_label_transform_queue(struct jump_entry *entry,
                                enum jump_label_type type);

extern void arch_jump_label_transform_apply(void);

static inline void jump_entry_set_init(struct jump_entry *entry,
                                       bool set)
{
    if (set)
        entry->key |= 2;
    else
        entry->key &= ~2;
}

#endif /* __ASSEMBLY__ */

#endif /* _LINUX_JUMP_LABEL_H */
