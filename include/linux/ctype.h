/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CTYPE_H
#define _LINUX_CTYPE_H

/*
 * NOTE! This ctype does not handle EOF like the standard C
 * library is required to.
 */

#define _U  0x01    /* upper */
#define _L  0x02    /* lower */
#define _D  0x04    /* digit */
#define _C  0x08    /* cntrl */
#define _P  0x10    /* punct */
#define _S  0x20    /* white space (space/lf/tab) */
#define _X  0x40    /* hex digit */
#define _SP 0x80    /* hard space (0x20) */

extern const unsigned char _ctype[];

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])

#define isalnum(c)  ((__ismask(c)&(_U|_L|_D)) != 0)

static inline int isdigit(int c)
{
    return '0' <= c && c <= '9';
}

/* Note: isspace() must return false for %NUL-terminator */
#define isspace(c)  ((__ismask(c)&(_S)) != 0)
#define isxdigit(c) ((__ismask(c)&(_D|_X)) != 0)
#define islower(c)  ((__ismask(c)&(_L)) != 0)
#define isupper(c)  ((__ismask(c)&(_U)) != 0)

/*
 * Fast implementation of tolower() for internal usage.
 * Do not use in your code.
 */
static inline char _tolower(const char c)
{
    return c | 0x20;
}

static inline unsigned char __tolower(unsigned char c)
{
    if (isupper(c))
        c -= 'A'-'a';
    return c;
}

static inline unsigned char __toupper(unsigned char c)
{
    if (islower(c))
        c -= 'a'-'A';
    return c;
}

#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)

#endif /* _LINUX_CTYPE_H */
