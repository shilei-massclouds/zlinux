/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_NODEMASK_H
#define __LINUX_NODEMASK_H

#include <linux/threads.h>
#include <linux/bitmap.h>
#include <linux/minmax.h>
#include <linux/numa.h>

#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#define NODE_MASK_ALL                           \
((nodemask_t) { {                           \
    [BITS_TO_LONGS(MAX_NUMNODES)-1] = NODE_MASK_LAST_WORD       \
} })

#define num_online_nodes()  num_node_state(N_ONLINE)

typedef struct { DECLARE_BITMAP(bits, MAX_NUMNODES); } nodemask_t;

/**
 * nodemask_pr_args - printf args to output a nodemask
 * @maskp: nodemask to be printed
 *
 * Can be used to provide arguments for '%*pb[l]' when printing a nodemask.
 */
#define nodemask_pr_args(maskp) \
    __nodemask_pr_numnodes(maskp), __nodemask_pr_bits(maskp)

static inline unsigned int __nodemask_pr_numnodes(const nodemask_t *m)
{
    return m ? MAX_NUMNODES : 0;
}
static inline const unsigned long *__nodemask_pr_bits(const nodemask_t *m)
{
    return m ? m->bits : NULL;
}

#define for_each_node_state(node, __state) \
    for ( (node) = 0; (node) == 0; (node) = 1)

#define first_online_node   0
#define first_memory_node   0
#define next_online_node(nid)   (MAX_NUMNODES)
#define nr_node_ids         1U
#define nr_online_nodes     1U

#define node_set_online(node)   node_set_state((node), N_ONLINE)
#define node_set_offline(node)  node_clear_state((node), N_ONLINE)

#define node_online(node)   node_state((node), N_ONLINE)
#define node_possible(node) node_state((node), N_POSSIBLE)

#define for_each_node(node) for_each_node_state(node, N_POSSIBLE)
#define for_each_online_node(node) for_each_node_state(node, N_ONLINE)

/*
 * Bitmasks that are kept for all the nodes.
 */
enum node_states {
    N_POSSIBLE,         /* The node could become online at some point */
    N_ONLINE,           /* The node is online */
    N_NORMAL_MEMORY,    /* The node has regular memory */
    N_HIGH_MEMORY = N_NORMAL_MEMORY,
    N_MEMORY,           /* The node has memory(regular, high, movable) */
    N_CPU,              /* The node has one or more cpus */
    N_GENERIC_INITIATOR,    /* The node has one or more Generic Initiators */
    NR_NODE_STATES
};

static inline int node_state(int node, enum node_states state)
{
    return node == 0;
}

static inline void node_set_state(int node, enum node_states state)
{
}

static inline void node_clear_state(int node, enum node_states state)
{
}

static inline int num_node_state(enum node_states state)
{
    return 1;
}

#endif /* __LINUX_NODEMASK_H */
