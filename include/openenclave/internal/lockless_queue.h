/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#ifndef _LOCKLESS_QUEUE_H_
#define _LOCKLESS_QUEUE_H_

#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

/* forward declaration */
struct _oe_lockless_queue_node;

#ifdef _MSC_VER
typedef struct _oe_lockless_queue_node* volatile atomic_lockless_node_ptr;
#elif defined __GNUC__
typedef struct _oe_lockless_queue_node* atomic_lockless_node_ptr;
#else
#error "unsupported"
#endif

/* struct oe_lockless_queue_node declaration */
/*---------------------------------------------------------------------------*/
typedef struct _oe_lockless_queue_node
{
    struct _oe_lockless_queue_node* p_link;
} oe_lockless_queue_node;

/* functions for oe_lockless_queue_node */
/*---------------------------------------------------------------------------*/
void oe_lockless_queue_node_init(oe_lockless_queue_node* p_node);

/* struct oe_lockless_queue declaration */
/*---------------------------------------------------------------------------*/
typedef struct _oe_lockless_queue
{
    atomic_lockless_node_ptr p_tail;
    atomic_lockless_node_ptr p_head;
} oe_lockless_queue;

/* functions for oe_lockless_queue */
/*---------------------------------------------------------------------------*/
void oe_lockless_queue_init(oe_lockless_queue* p_queue);

void oe_lockless_queue_push_back(
    oe_lockless_queue* p_queue,
    oe_lockless_queue_node* p_node);

oe_lockless_queue_node* oe_lockless_queue_pop_front(oe_lockless_queue* p_queue);

OE_EXTERNC_END

#endif /* _LOCKLESS_QUEUE_H_ */
