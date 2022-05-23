/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JUMP_LABEL_H
#define _LINUX_JUMP_LABEL_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/bug.h>

struct static_key {
    atomic_t enabled;
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

#endif /* __ASSEMBLY__ */

#endif /* _LINUX_JUMP_LABEL_H */
