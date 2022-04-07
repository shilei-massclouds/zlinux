/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_FLS64_H_
#define _ASM_GENERIC_BITOPS_FLS64_H_

static __always_inline int fls64(__u64 x)
{
    if (x == 0)
        return 0;
    return __fls(x) + 1;
}

#endif /* _ASM_GENERIC_BITOPS_FLS64_H_ */
