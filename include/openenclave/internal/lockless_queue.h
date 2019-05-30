/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#ifndef _LOCKLESS_QUEUE_H_
#define _LOCKLESS_QUEUE_H_

#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

/* forward declarations */
struct _oe_lockless_queue_node;
struct _oe_lockless_queue;

/**
 * @typedef atomic_lockless_node_ptr
 *
 * @brief A platform abstract pointer to a lockless_queue_node.
 */
#ifdef _MSC_VER
typedef struct _oe_lockless_queue_node* volatile atomic_lockless_node_ptr;
#elif defined __GNUC__
typedef struct _oe_lockless_queue_node* atomic_lockless_node_ptr;
#else
#error "unsupported"
#endif

/**
 * @struct _oe_lockless_queue_node
 *
 * @brief The basic structure for a lockless queue node.
 *
 * This structure is the basic node used with struct _oe_lockless queue.
 *
 * @note This should be initialized with oe_lockless_queue_node_init() before
 *       use.
 *
 * @see _oe_lockless_queue
 * @see oe_lockless_queue_node_init()
 */
typedef struct _oe_lockless_queue_node
{
    /**
     * @internal
     */
    struct _oe_lockless_queue_node* p_link;
} oe_lockless_queue_node;

/**
 * @function oe_lockless_queue_node_init
 *
 * @brief Initializes an _oe_lockless_queue_node.
 *
 * Prepares a node for use with _oe_lockless_queue.
 *
 * @param p_node An uninitialized _oe_lockless_queue_node.
 *
 * @pre p_node is non-NULL and points to an unitialized node.
 * @post p_node is prepared to pass to oe_lockless_queue_push_back().
 */
void oe_lockless_queue_node_init(oe_lockless_queue_node* p_node);

/**
 * @struct _oe_lockless_queue
 *
 * @brief The structure for managing a multi-producer, single-consumer, FIFO
 *        queue data structure that is multithread stable.
 *
 * This structure is the basic control data type for a thread-safe lockless FIFO
 * queue.  This data structure allows any number of threads to call
 * oe_lockless_queue_push_back() and one thread to call
 * oe_lockless_queue_pop_front() concurrently without the use of any mutex while
 * maintaining a consistent and stable state.
 *
 * @note This should be initialized with oe_lockless_queue_init() before use.
 *
 * @see oe_lockless_queue_node_init()
 * @see oe_lockless_queue_push_front()
 * @see oe_lockless_queue_pop_back()
 */
typedef struct _oe_lockless_queue
{
    /**
     * @internal
     */
    atomic_lockless_node_ptr p_tail;
    /**
     * @internal
     */
    atomic_lockless_node_ptr p_head;
} oe_lockless_queue;

/**
 * @function oe_lockless_queue_init
 *
 * @brief Initializes an _oe_lockless_queue_node.
 *
 * Prepares an _oe_lockless_queue for use.
 *
 * @param p_queue An uninitialized _oe_lockless_queue.
 *
 * @pre p_queue is non-NULL and points to an unitialized queue.
 * @post p_queue is prepared to use with oe_lockless_queue_push_back() and
 * oe_lockless_queue_pop_front().
 */
void oe_lockless_queue_init(oe_lockless_queue* p_queue);

/**
 * @function oe_lockless_queue_push_back
 *
 * @brief Appends an _oe_lockless_queue node to the tail end of an
 *        _oe_lockless_queue.
 *
 * @param p_queue The _oe_lockless_queue to append the node.
 * @param p_node The _oe_lockless_queue_node to append to the queue.
 *
 * @pre p_queue is non-NULL and points to an initialized queue and p_node is
 *      non-NULL and points to an initialized node.
 * @post p_node has been appended to the end of p_queue.
 *
 * @note It is safe to call this method from any number of threads concurrently.
 *       It is also safe to call this method concurrently while also calling
 *       oe_lockless_queue_pop_front() from a single thread.
 */
void oe_lockless_queue_push_back(
    oe_lockless_queue* p_queue,
    oe_lockless_queue_node* p_node);

/**
 * @function oe_lockless_queue_pop_front
 *
 * @brief Attempts to remove and return an _oe_lockless_queue_node from the head
 *        of an _oe_lockless_queue.
 *
 * @param p_queue The _oe_lockless_queue to remove a node from.
 * @return A pointer to an _oe_lockless_queue_node if there was at least one in
 *         the queue or NULL if there was not a node in the queue.
 * @pre p_queue is non-NULL and points to an initialized queue and p_node is
 *      non-NULL and points to an initialized node.
 *
 * @note It is not safe to call this method concurrently from more than one
 *       thread.  However it is safe to call this method while concurrently
 *       calling oe_lockless_queue_push_back() from any number of threads.
 */
oe_lockless_queue_node* oe_lockless_queue_pop_front(oe_lockless_queue* p_queue);

OE_EXTERNC_END

#endif /* _LOCKLESS_QUEUE_H_ */
