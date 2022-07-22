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
