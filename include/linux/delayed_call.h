/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DELAYED_CALL_H
#define _DELAYED_CALL_H

/*
 * Poor man's closures; I wish we could've done them sanely polymorphic,
 * but...
 */

struct delayed_call {
    void (*fn)(void *);
    void *arg;
};

#endif /* _DELAYED_CALL_H */
