/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_BIT_H
#define _LINUX_WAIT_BIT_H

/*
 * Linux wait-bit related types and methods:
 */
#include <linux/wait.h>

struct wait_bit_key {
    void            *flags;
    int             bit_nr;
    unsigned long   timeout;
};

struct wait_bit_queue_entry {
    struct wait_bit_key key;
    struct wait_queue_entry wq_entry;
};

#define __WAIT_BIT_KEY_INITIALIZER(word, bit) \
    { .flags = word, .bit_nr = bit, }

int wake_bit_function(struct wait_queue_entry *wq_entry,
                      unsigned mode, int sync, void *key);

#define DEFINE_WAIT_BIT(name, word, bit)                    \
    struct wait_bit_queue_entry name = {                    \
        .key = __WAIT_BIT_KEY_INITIALIZER(word, bit),       \
        .wq_entry = {                                       \
            .private    = current,                          \
            .func       = wake_bit_function,                \
            .entry      =                                   \
                LIST_HEAD_INIT((name).wq_entry.entry),      \
        },                                                  \
    }

typedef int wait_bit_action_f(struct wait_bit_key *key, int mode);

extern int bit_wait(struct wait_bit_key *key, int mode);
extern int bit_wait_io(struct wait_bit_key *key, int mode);
extern int bit_wait_timeout(struct wait_bit_key *key, int mode);
extern int bit_wait_io_timeout(struct wait_bit_key *key, int mode);

/**
 * wait_on_bit_lock_io - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared and then to atomically set it.  This is similar
 * to wait_on_bit(), but calls io_schedule() instead of schedule()
 * for the actual waiting.
 *
 * Returns zero if the bit was (eventually) found to be clear and was
 * set.  Returns non-zero if a signal was delivered to the process and
 * the @mode allows that signal to wake the process.
 */
static inline int
wait_on_bit_lock_io(unsigned long *word, int bit, unsigned mode)
{
    might_sleep();
    if (!test_and_set_bit(bit, word))
        return 0;
#if 0
    return out_of_line_wait_on_bit_lock(word, bit, bit_wait_io, mode);
#endif
    panic("%s: END!\n", __func__);
}

extern void __init wait_bit_init(void);

void __wake_up_bit(struct wait_queue_head *wq_head, void *word, int bit);

void wake_up_bit(void *word, int bit);

int out_of_line_wait_on_bit(void *word, int, wait_bit_action_f *action,
                            unsigned int mode);

int out_of_line_wait_on_bit_timeout(void *word, int, wait_bit_action_f *action,
                                    unsigned int mode, unsigned long timeout);

int out_of_line_wait_on_bit_lock(void *word, int, wait_bit_action_f *action,
                                 unsigned int mode);

/**
 * wait_on_bit_io - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared.  This is similar to wait_on_bit(), but calls
 * io_schedule() instead of schedule() for the actual waiting.
 *
 * Returned value will be zero if the bit was cleared, or non-zero
 * if the process received a signal and the mode permitted wakeup
 * on that signal.
 */
static inline int
wait_on_bit_io(unsigned long *word, int bit, unsigned mode)
{
    might_sleep();
    if (!test_bit(bit, word))
        return 0;
    return out_of_line_wait_on_bit(word, bit, bit_wait_io, mode);
}

#endif /* _LINUX_WAIT_BIT_H */
