/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <uapi/linux/string.h>

#ifndef __HAVE_ARCH_STRCMP
extern int strcmp(const char *,const char *);
#endif

#ifndef __HAVE_ARCH_STRLEN
extern __kernel_size_t strlen(const char *);
#endif

#ifndef __HAVE_ARCH_STRRCHR
extern char * strrchr(const char *,int);
#endif

#ifndef __HAVE_ARCH_MEMCMP
extern int memcmp(const void *,const void *,__kernel_size_t);
#endif

#ifndef __HAVE_ARCH_MEMCPY
extern void * memcpy(void *,const void *,__kernel_size_t);
#endif

#ifndef __HAVE_ARCH_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef __HAVE_ARCH_MEMCHR
extern void * memchr(const void *,int,__kernel_size_t);
#endif

#endif /* _LINUX_STRING_H_ */
