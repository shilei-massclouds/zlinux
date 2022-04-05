/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */

#ifndef _UAPI_LINUX_CONST_H
#define _UAPI_LINUX_CONST_H

#ifdef __ASSEMBLY__
#define _AC(X,Y)    X
#else
#define __AC(X,Y)   (X##Y)
#define _AC(X,Y)    __AC(X,Y)
#endif

#endif /* _UAPI_LINUX_CONST_H */
