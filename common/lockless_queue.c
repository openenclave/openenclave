// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/lockless_queue.h>
#include <stdlib.h>

/* functions for lockless_queue_node */
/*---------------------------------------------------------------------------*/
void init_lockless_queue_node(lockless_queue_node* p_node)
{
    p_node->p_link = NULL;
} /* init_lockless_queue_node */

/* functions for lockless_queue */
/*---------------------------------------------------------------------------*/
void init_lockless_queue(lockless_queue* p_queue)
{
#ifdef _MSC_VER
    InterlockedExchangePointer(&(p_queue->p_tail), NULL);
    InterlockedExchangePointer(&(p_queue->p_head), NULL);
#elif defined __GNUC__
    __atomic_store_n(&(p_queue->p_tail), NULL, __ATOMIC_RELAXED);
    __atomic_store_n(&(p_queue->p_head), NULL, __ATOMIC_RELAXED);
#endif // __GNUC__
} /* init_lockless_queue */

void lockless_queue_push(lockless_queue* p_queue, lockless_queue_node* p_node)
{
    lockless_queue_node* p_expected = NULL;
#ifdef _MSC_VER
    lockless_queue_node* p_actual = NULL;
#endif // _MSC_VER
    do
    {
#ifdef _MSC_VER
        p_expected = p_actual;
        p_node->p_link = p_expected;
        p_actual = (lockless_queue_node*)InterlockedCompareExchangePointer(
            &(p_queue->p_tail), p_node, p_expected);
    } while (p_actual != p_expected);
#elif defined __GNUC__
        p_node->p_link = p_expected;
    } while (!__atomic_compare_exchange_n(
        &(p_queue->p_tail),
        &p_expected,
        p_node,
        1,
        __ATOMIC_ACQ_REL,
        __ATOMIC_ACQUIRE));
#endif // __GNUC__
} /* lockless_queue_push */

lockless_queue_node* lockless_queue_pop(lockless_queue* p_queue)
{
    // try to take a node from the head
    lockless_queue_node* popped_node = NULL;
#ifdef _MSC_VER
    popped_node = (lockless_queue_node*)InterlockedCompareExchangePointer(
        &(p_queue->p_head), NULL, NULL);
#elif defined __GNUC__
    popped_node = __atomic_load_n(&(p_queue->p_head), __ATOMIC_ACQUIRE);
#endif // __GNUC__

    if (NULL != popped_node)
    {
        // there was a node at the head
        // pop the node from the head and replace it with the node that it
        //     points to
        // remove the reference from the popped node to the next node
        lockless_queue_node* next_node = popped_node->p_link;
        popped_node->p_link = NULL;
#ifdef _MSC_VER
        InterlockedExchangePointer(&(p_queue->p_head), next_node);
#elif defined __GNUC__
        __atomic_store_n(&(p_queue->p_head), next_node, __ATOMIC_RELEASE);
#endif // __GNUC__
    }
    else
    {
        // there wasn't a node at the head
        // so refill the head with the nodes from the tail
#ifdef _MSC_VER
        popped_node = (lockless_queue_node*)InterlockedCompareExchangePointer(
            &(p_queue->p_tail), NULL, NULL);
#elif defined __GNUC__
        popped_node = __atomic_load_n(&(p_queue->p_tail), __ATOMIC_RELAXED);
#endif // __GNUC__

        if (NULL != popped_node)
        {
            // take all of the nodes off of the tail
#ifdef _MSC_VER
            lockless_queue_node* p_actual = NULL;
            while (popped_node !=
                   (p_actual =
                        (lockless_queue_node*)InterlockedCompareExchangePointer(
                            &(p_queue->p_tail), NULL, popped_node)))
            {
                popped_node = p_actual;
            }
#elif defined __GNUC__
            while (!__atomic_compare_exchange_n(
                &(p_queue->p_tail),
                &popped_node,
                NULL,
                1,
                __ATOMIC_ACQ_REL,
                __ATOMIC_ACQUIRE))
            {
                continue;
            }
#endif // __GNUC__

            // reverse the nodes from the tail
            lockless_queue_node* prev_node = NULL;
            lockless_queue_node* next_node = NULL;
            next_node = popped_node->p_link;
            while (NULL != next_node)
            {
                popped_node->p_link = prev_node;
                prev_node = popped_node;
                popped_node = next_node;
                next_node = popped_node->p_link;
            }

            // move the nodes to the head
            popped_node->p_link = NULL;
#if _MSC_VER
            InterlockedExchangePointer(&(p_queue->p_head), prev_node);
#elif defined __GNUC__
            __atomic_store_n(&(p_queue->p_head), prev_node, __ATOMIC_RELEASE);
#endif // __GNUC__
        }
    }
    return popped_node;
} /* lockless_queue_pop */
