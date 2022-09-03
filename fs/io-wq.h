#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>

struct io_wq;

struct io_wq_work_node {
    struct io_wq_work_node *next;
};

struct io_wq_work_list {
    struct io_wq_work_node *first;
    struct io_wq_work_node *last;
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
typedef void (io_wq_work_fn)(struct io_wq_work *);

extern void io_wq_worker_sleeping(struct task_struct *);
extern void io_wq_worker_running(struct task_struct *);

#endif /* INTERNAL_IO_WQ_H */
