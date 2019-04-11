// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LOCKLESS_QUEUE_H_
#define _LOCKLESS_QUEUE_H_

#if _MSC_VER
#include <Windows.h>
#endif

#ifndef EXTERN
#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN
#endif
#endif

/* forward declaration */
struct _lockless_queue_node;

#ifdef _MSC_VER
typedef struct _lockless_queue_node* volatile atomic_lockless_node_ptr;
#elif defined __GNUC__
typedef struct _lockless_queue_node* atomic_lockless_node_ptr;
#else
#error "unsupported"
#endif

/* struct lockless_queue_node declaration */
/*---------------------------------------------------------------------------*/
typedef struct _lockless_queue_node
{
    struct _lockless_queue_node* p_link;
} lockless_queue_node;

/* functions for lockless_queue_node */
/*---------------------------------------------------------------------------*/
EXTERN void init_lockless_queue_node(lockless_queue_node* p_node);

/* struct lockless_queue declaration */
/*---------------------------------------------------------------------------*/
typedef struct _lockless_queue
{
    atomic_lockless_node_ptr p_tail;
    atomic_lockless_node_ptr p_head;
} lockless_queue;

/* functions for lockless_queue */
/*---------------------------------------------------------------------------*/
EXTERN void init_lockless_queue(lockless_queue* p_queue);

EXTERN void lockless_queue_push(
    lockless_queue* p_queue,
    lockless_queue_node* p_node);

EXTERN lockless_queue_node* lockless_queue_pop(lockless_queue* p_queue);

#endif // _LOCKLESS_QUEUE_H_
