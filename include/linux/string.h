/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <linux/compiler.h> /* for inline */
#include <linux/types.h>    /* for size_t */
#include <linux/stddef.h>   /* for NULL */
#include <stdarg.h>
#include <uapi/linux/string.h>

/*
 * Include machine specific inline routines
 */
#include <asm/string.h>

#ifndef __HAVE_ARCH_STRCPY
extern char * strcpy(char *,const char *);
#endif

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

#ifndef __HAVE_ARCH_STRNCMP
extern int strncmp(const char *,const char *,__kernel_size_t);
#endif

#ifndef __HAVE_ARCH_MEMMOVE
extern void * memmove(void *,const void *,__kernel_size_t);
#endif

#ifndef __HAVE_ARCH_STRSTR
extern char * strstr(const char *, const char *);
#endif

#ifndef __HAVE_ARCH_STRCHR
extern char * strchr(const char *,int);
#endif

#ifndef __HAVE_ARCH_STRCHRNUL
extern char * strchrnul(const char *,int);
#endif

#ifndef __HAVE_ARCH_STRCSPN
extern __kernel_size_t strcspn(const char *,const char *);
#endif

#ifndef __HAVE_ARCH_STRSPN
extern __kernel_size_t strspn(const char *,const char *);
#endif

#ifndef __HAVE_ARCH_STRNLEN
extern __kernel_size_t strnlen(const char *,__kernel_size_t);
#endif

#ifndef __HAVE_ARCH_STRCASECMP
extern int strcasecmp(const char *s1, const char *s2);
#endif

#ifndef __HAVE_ARCH_STRNCHR
extern char * strnchr(const char *, size_t, int);
#endif

#ifndef __HAVE_ARCH_STRPBRK
extern char * strpbrk(const char *,const char *);
#endif

#ifndef __HAVE_ARCH_STRSEP
extern char * strsep(char **,const char *);
#endif

#ifndef __HAVE_ARCH_STRLCAT
extern size_t strlcat(char *, const char *, __kernel_size_t);
#endif

extern char * __must_check skip_spaces(const char *);

/**
 * kbasename - return the last part of a pathname.
 *
 * @path: path to extract the filename from.
 */
static inline const char *kbasename(const char *path)
{
    const char *tail = strrchr(path, '/');
    return tail ? tail + 1 : path;
}

extern void kfree_const(const void *x);

extern char *kstrdup(const char *s, gfp_t gfp) __malloc;
extern const char *kstrdup_const(const char *s, gfp_t gfp);

char *strreplace(char *s, char old, char new);

#endif /* _LINUX_STRING_H_ */
