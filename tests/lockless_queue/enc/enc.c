/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#include <lockless_queue_t.h>
#include <openenclave/internal/tests.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif /* _MSC_VER */

void enc_push_nodes(
    oe_lockless_queue* p_queue,
    test_node* p_nodes,
    size_t count)
{
    /* push the nodes onto the queue */
    for (size_t i = 0; i < count; ++i)
    {
        oe_lockless_queue_push_back(p_queue, &((p_nodes + i)->_node));
    }
} /* enc_push_nodes */

void enc_writer_thread(
    oe_lockless_queue* p_queue,
    test_node* p_nodes,
    size_t* p_barrier)
{
    size_t barrier_count;

    /* wait for all of the threads to start */
#ifdef _MSC_VER
    barrier_count = _InterlockedIncrement64(data->p_barrier);
    while (barrier_count < THREAD_COUNT)
    {
        barrier_count = _InterlockedCompareExchange64 (data->p_barrier, 0, 0));
    }
#elif defined __GNUC__
    barrier_count = __atomic_add_fetch(p_barrier, 1, __ATOMIC_ACQ_REL);
    while (THREAD_COUNT > barrier_count)
    {
        barrier_count = __atomic_load_n(p_barrier, __ATOMIC_ACQUIRE);
    }
#endif /* _MSC_VER or __GNUC__ */

    /* push this thread's nodes onto the queue */
    enc_push_nodes(p_queue, p_nodes, TEST_COUNT);
} /* enc_writer_thread */

void enc_pop_nodes(oe_lockless_queue* p_queue, size_t count)
{
    size_t node_count = 0;

    /* pop the nodes off of the queue */
    while (node_count < count)
    {
        oe_lockless_queue_node* p_node = oe_lockless_queue_pop_front(p_queue);
        if (NULL != p_node)
        {
            test_node* p_test_node = (test_node*)p_node;
            ++(p_test_node->count);
            p_test_node->pop_order = node_count;
            ++node_count;
        }
    }
} /* enc_pop_nodes */

void enc_test_queue_single_threaded()
{
    oe_lockless_queue queue;
    oe_lockless_queue_node nodes[TEST_COUNT];
    oe_lockless_queue_node* p_node = NULL;

    oe_lockless_queue_init(&queue);

    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    for (size_t i = 0; i < (TEST_COUNT); ++i)
    {
        oe_lockless_queue_node_init(nodes + i);
    }

    for (size_t i = 0; i < (TEST_COUNT); ++i)
    {
        oe_lockless_queue_push_back(&queue, nodes + i);
    }

    for (size_t i = 0; i < (TEST_COUNT); ++i)
    {
        p_node = oe_lockless_queue_pop_front(&queue);
        OE_TEST(p_node == nodes + i);
    }
} /* enc_test_queue_single_threaded */

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
