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

extern void fput(struct file *);
extern void fput_many(struct file *, unsigned int);

extern int f_dupfd(unsigned int from, struct file *file, unsigned flags);
extern int replace_fd(unsigned fd, struct file *file, unsigned flags);
extern void set_close_on_exec(unsigned int fd, int flag);
extern bool get_close_on_exec(unsigned int fd);
extern int __get_unused_fd_flags(unsigned flags, unsigned long nofile);
extern int get_unused_fd_flags(unsigned flags);
extern void put_unused_fd(unsigned int fd);

#endif /* __LINUX_FILE_H */
