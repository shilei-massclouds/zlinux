/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/posix_types.h>
#include <linux/errno.h>

struct file;

struct fd {
    struct file *file;
    unsigned int flags;
};
#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

extern void fput(struct file *);
extern void fput_many(struct file *, unsigned int);

static inline void fdput(struct fd fd)
{
    if (fd.flags & FDPUT_FPUT)
        fput(fd.file);
}

extern int f_dupfd(unsigned int from, struct file *file, unsigned flags);
extern int replace_fd(unsigned fd, struct file *file, unsigned flags);
extern void set_close_on_exec(unsigned int fd, int flag);
extern bool get_close_on_exec(unsigned int fd);
extern int __get_unused_fd_flags(unsigned flags, unsigned long nofile);
extern int get_unused_fd_flags(unsigned flags);
extern void put_unused_fd(unsigned int fd);

extern void fd_install(unsigned int fd, struct file *file);

static inline struct fd __to_fd(unsigned long v)
{
    return (struct fd){(struct file *)(v & ~3),v & 3};
}

extern unsigned long __fdget_pos(unsigned int fd);

static inline struct fd fdget_pos(int fd)
{
    return __to_fd(__fdget_pos(fd));
}

extern void __f_unlock_pos(struct file *);

static inline void fdput_pos(struct fd f)
{
    if (f.flags & FDPUT_POS_UNLOCK)
        __f_unlock_pos(f.file);
    fdput(f);
}

extern unsigned long __fdget_raw(unsigned int fd);

static inline struct fd fdget_raw(unsigned int fd)
{
    return __to_fd(__fdget_raw(fd));
}

extern struct file *fget(unsigned int fd);
extern struct file *fget_many(unsigned int fd, unsigned int refs);
extern struct file *fget_raw(unsigned int fd);
extern struct file *fget_task(struct task_struct *task, unsigned int fd);
extern unsigned long __fdget(unsigned int fd);

#endif /* __LINUX_FILE_H */
