/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SEM_H
#define _LINUX_SEM_H

//#include <uapi/linux/sem.h>

struct task_struct;
struct sem_undo_list;

struct sysv_sem {
    struct sem_undo_list *undo_list;
};

extern int copy_semundo(unsigned long clone_flags,
                        struct task_struct *tsk);
extern void exit_sem(struct task_struct *tsk);

#endif /* _LINUX_SEM_H */
