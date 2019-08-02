/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#include <openenclave/bits/lockless_queue.h>
#include <stdlib.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#endif /* OE_BUILD_ENCLAVE */

#ifdef _MSC_VER
#include <intrin.h>
#endif /* _MSC_VER */

/* functions for oe_lockless_queue_node */
/*---------------------------------------------------------------------------*/
void oe_lockless_queue_node_init(oe_lockless_queue_node* p_node)
{
    p_node->p_link = NULL;
} /* init_oe_lockless_queue_node */

/* functions for oe_lockless_queue */
/*---------------------------------------------------------------------------*/
void oe_lockless_queue_init(oe_lockless_queue* p_queue)
{
#ifdef _MSC_VER
    _InterlockedExchangePointer(&(p_queue->p_tail), NULL);
    _InterlockedExchangePointer(&(p_queue->p_head), NULL);
#elif defined __GNUC__
    __atomic_store_n(&(p_queue->p_tail), NULL, __ATOMIC_RELAXED);
    __atomic_store_n(&(p_queue->p_head), NULL, __ATOMIC_RELAXED);
#endif /* _MSC_VER or __GNUC__ */
} /* init_oe_lockless_queue */

void oe_lockless_queue_push_back(
    oe_lockless_queue* p_queue,
    oe_lockless_queue_node* p_node)
{
    oe_lockless_queue_node* p_expected = NULL;
#ifdef _MSC_VER
    oe_lockless_queue_node* p_actual = NULL;
#endif /* _MSC_VER */
    do
    {
#ifdef _MSC_VER
        p_expected = p_actual;
        p_node->p_link = p_expected;
        p_actual = (oe_lockless_queue_node*)_InterlockedCompareExchangePointer(
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
#endif /* _MSC_VER or __GNUC__ */
} /* oe_lockless_queue_push_back */

oe_lockless_queue_node* oe_lockless_queue_pop_front(oe_lockless_queue* p_queue)
{
    /* try to take a node from the head */
    oe_lockless_queue_node* popped_node = NULL;
#ifdef _MSC_VER
    popped_node = (oe_lockless_queue_node*)_InterlockedCompareExchangePointer(
        &(p_queue->p_head), NULL, NULL);
#elif defined __GNUC__
    popped_node = __atomic_load_n(&(p_queue->p_head), __ATOMIC_ACQUIRE);
#endif /* _MSC_VER or __GNUC__ */

    if (NULL != popped_node)
    {
        /* there was a node at the head
         * pop the node from the head and replace it with the node that it
         *     points to
         * remove the reference from the popped node to the next node */
        oe_lockless_queue_node* next_node = popped_node->p_link;
        popped_node->p_link = NULL;
#ifdef _MSC_VER
        _InterlockedExchangePointer(&(p_queue->p_head), next_node);
#elif defined __GNUC__
        __atomic_store_n(&(p_queue->p_head), next_node, __ATOMIC_RELEASE);
#endif /* _MSC_VER or __GNUC__ */
    }
    else
    {
        /* there wasn't a node at the head
         * so refill the head with the nodes from the tail */

        /* take all of the nodes off of the tail */
#ifdef _MSC_VER
        popped_node = (oe_lockless_queue_node*)_InterlockedExchangePointer(
            &(p_queue->p_tail), NULL);
#elif defined __GNUC__
        popped_node =
            __atomic_exchange_n(&(p_queue->p_tail), NULL, __ATOMIC_ACQ_REL);
#endif /* _MSC_VER or __GNUC__ */

        if (NULL != popped_node)
        {
            /* reverse the nodes from the tail */
            oe_lockless_queue_node* prev_node = NULL;
            oe_lockless_queue_node* next_node = NULL;
            next_node = popped_node->p_link;
            while (NULL != next_node)
            {
                popped_node->p_link = prev_node;
                prev_node = popped_node;
                popped_node = next_node;
                next_node = popped_node->p_link;
            }

            /* move the nodes to the head */
            popped_node->p_link = NULL;
#if _MSC_VER
            _InterlockedExchangePointer(&(p_queue->p_head), prev_node);
#elif defined __GNUC__
            __atomic_store_n(&(p_queue->p_head), prev_node, __ATOMIC_RELEASE);
#endif /* _MSC_VER or __GNUC__ */
        }
    }
    return popped_node;
} /* oe_lockless_queue_pop_front */

oe_result_t oe_lockless_queue_unsafe_pop_front(
    oe_lockless_queue* p_queue,
    oe_lockless_queue_node** pp_node_out)
{
    /* try to take a node from the head */
    oe_result_t result = OE_FAILURE;
    oe_lockless_queue_node* popped_node = NULL;
#ifdef _MSC_VER
    popped_node = (oe_lockless_queue_node*)_InterlockedCompareExchangePointer(
        &(p_queue->p_head), NULL, NULL);
#elif defined __GNUC__
    popped_node = __atomic_load_n(&(p_queue->p_head), __ATOMIC_ACQUIRE);
#endif /* _MSC_VER or __GNUC__ */

    if (NULL != popped_node)
    {
        /* there was a node at the head
         * pop the node from the head and replace it with the node that it
         *     points to
         * remove the reference from the popped node to the next node */

        /* all of the nodes that are in the head stack have been validated
         * already in the else block below */
        oe_lockless_queue_node* next_node = popped_node->p_link;
        popped_node->p_link = NULL;
#ifdef _MSC_VER
        _InterlockedExchangePointer(&(p_queue->p_head), next_node);
#elif defined __GNUC__
        __atomic_store_n(&(p_queue->p_head), next_node, __ATOMIC_RELEASE);
#endif /* _MSC_VER or __GNUC__ */
        *pp_node_out = popped_node;
        result = OE_OK;
    }
    else
    {
        /* there wasn't a node at the head
         * so refill the head with the nodes from the tail */

        /* take all of the nodes off of the tail */
#ifdef _MSC_VER
        popped_node = (oe_lockless_queue_node*)_InterlockedExchangePointer(
            &(p_queue->p_tail), NULL);
#elif defined __GNUC__
        popped_node =
            __atomic_exchange_n(&(p_queue->p_tail), NULL, __ATOMIC_ACQ_REL);
#endif /* _MSC_VER or __GNUC__ */

        if (NULL != popped_node)
        {
            /* reverse the nodes from the tail */
            oe_lockless_queue_node* prev_node = NULL;
            oe_lockless_queue_node* next_node = NULL;
            /* test that popped_node is outside of enclave memory before writing
             * to it */
#ifdef OE_BUILD_ENCLAVE
            if (oe_is_outside_enclave(
                    popped_node, sizeof(oe_lockless_queue_node)))
#endif /* OE_BUILD_ENCLAVE */
            {
                next_node = popped_node->p_link;
                while (NULL != next_node)
                {
                    popped_node->p_link = prev_node;
                    prev_node = popped_node;
                    popped_node = next_node;
#ifdef OE_BUILD_ENCLAVE
                    if (oe_is_outside_enclave(
                            popped_node, sizeof(oe_lockless_queue_node)))
#endif /* OE_BUILD_ENCLAVE */
                    {
                        next_node = popped_node->p_link;
                    }
#ifdef OE_BUILD_ENCLAVE
                    else
                    {
                        /* popped node is outside of enclave memory
                         * set popped_node and next_node to NULL and this will
                         * be handled */
                        popped_node = next_node = NULL;
                    }
#endif /* OE_BUILD_ENCLAVE */
                }
            }
#ifdef OE_BUILD_ENCLAVE
            else
            {
                /* popped_node is not outside of enclave memory
                 * set popped_node to NULL and this will be handled */
                popped_node = NULL;
            }
#endif /* OE_BUILD_ENCLAVE */

            if (NULL != popped_node)
            {
                /* popped_node is not NULL so assign the popped_node to
                 * pp_node_out and set the result to OE_OK */
                /* move the nodes to the head */
                popped_node->p_link = NULL;
#if _MSC_VER
                _InterlockedExchangePointer(&(p_queue->p_head), prev_node);
#elif defined __GNUC__
                __atomic_store_n(
                    &(p_queue->p_head), prev_node, __ATOMIC_RELEASE);
#endif /* _MSC_VER or __GNUC__ */
                *pp_node_out = popped_node;
                result = OE_OK;
            }
        }
        else
        {
            /* the queue is empty */
            *pp_node_out = NULL;
            result = OE_OK;
        }
    }
    return result;
} /* oe_lockless_queue_unsafe_pop_front */
