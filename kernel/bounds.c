// SPDX-License-Identifier: GPL-2.0
/*
 * Generate definitions needed by the preprocessor.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#define __GENERATING_BOUNDS_H
/* Include headers that define the enum constants of interest */
#include <linux/page-flags.h>
#include <linux/mmzone.h>
#include <linux/kbuild.h>
/*
#include <linux/log2.h>
#include <linux/spinlock_types.h>
*/

int main(void)
{
    /* The enum constants to put into include/generated/bounds.h */
    DEFINE(MAX_NR_ZONES, __MAX_NR_ZONES);
    /* End of constants */

    return 0;
}
