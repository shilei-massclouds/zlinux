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

#endif /* _LINUX_WAIT_BIT_H */
