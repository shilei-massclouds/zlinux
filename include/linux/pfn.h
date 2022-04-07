/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PFN_H_
#define _LINUX_PFN_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>

#endif /* !__ASSEMBLY__ */

#define PFN_UP(x)   (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_DOWN(x) ((x) >> PAGE_SHIFT)

#endif /* _LINUX_PFN_H_ */
