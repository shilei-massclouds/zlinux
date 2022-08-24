// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/lockref.h>

/**
 * lockref_get - Increments reference count unconditionally
 * @lockref: pointer to lockref structure
 *
 * This operation is only valid if you already hold a reference
 * to the object, so you know the count cannot be zero.
 */
void lockref_get(struct lockref *lockref)
{
    spin_lock(&lockref->lock);
    lockref->count++;
    spin_unlock(&lockref->lock);
}
EXPORT_SYMBOL(lockref_get);

/**
 * lockref_get_not_dead - Increments count unless the ref is dead
 * @lockref: pointer to lockref structure
 * Return: 1 if count updated successfully or 0 if lockref was dead
 */
int lockref_get_not_dead(struct lockref *lockref)
{
    int retval;

    spin_lock(&lockref->lock);
    retval = 0;
    if (lockref->count >= 0) {
        lockref->count++;
        retval = 1;
    }
    spin_unlock(&lockref->lock);
    return retval;
}
EXPORT_SYMBOL(lockref_get_not_dead);

/**
 * lockref_put_or_lock - decrements count unless count <= 1 before decrement
 * @lockref: pointer to lockref structure
 * Return: 1 if count updated successfully or 0 if count <= 1 and lock taken
 */
int lockref_put_or_lock(struct lockref *lockref)
{
    spin_lock(&lockref->lock);
    if (lockref->count <= 1)
        return 0;
    lockref->count--;
    spin_unlock(&lockref->lock);
    return 1;
}
EXPORT_SYMBOL(lockref_put_or_lock);

/**
 * lockref_put_return - Decrement reference count if possible
 * @lockref: pointer to lockref structure
 *
 * Decrement the reference count and return the new value.
 * If the lockref was dead or locked, return an error.
 */
int lockref_put_return(struct lockref *lockref)
{
    return -1;
}
EXPORT_SYMBOL(lockref_put_return);

/**
 * lockref_mark_dead - mark lockref dead
 * @lockref: pointer to lockref structure
 */
void lockref_mark_dead(struct lockref *lockref)
{
    assert_spin_locked(&lockref->lock);
    lockref->count = -128;
}
EXPORT_SYMBOL(lockref_mark_dead);
