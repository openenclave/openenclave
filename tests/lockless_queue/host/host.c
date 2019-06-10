/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#include <lockless_queue_u.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
//#include <intrin.h>
#include <Windows.h>
#elif defined __GNUC__
#include <pthread.h>
#endif /* _MSC_VER or __GNUC__ */

#ifdef _MSC_VER

#define THREAD_RETURN_TYPE DWORD WINAPI
#define THREAD_ARG_TYPE LPVOID
#define THREAD_RETURN_VAL 0
#define THREAD_TYPE HANDLE

typedef DWORD (*thread_op_t)(THREAD_ARG_TYPE);

int thread_create(THREAD_TYPE* thread, thread_op_t op, THREAD_ARG_TYPE arg)
{
    *thread = CreateThread(NULL, 0, op, arg, 0, NULL);
    return NULL == *thread;
} /* thread_create */

void thread_join(THREAD_TYPE thread)
{
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
} /* thread_join */

#elif defined __GNUC__

#define THREAD_RETURN_TYPE void*
#define THREAD_ARG_TYPE void*
#define THREAD_RETURN_VAL NULL
#define THREAD_TYPE pthread_t

typedef THREAD_RETURN_TYPE (*thread_op_t)(THREAD_ARG_TYPE);

int thread_create(THREAD_TYPE* thread, thread_op_t op, THREAD_ARG_TYPE arg)
{
    return pthread_create(thread, NULL, op, arg);
} /* thread_create */

void thread_join(THREAD_TYPE thread)
{
    pthread_join(thread, NULL);
} /* thread_join */

#endif /* _MSC_VER or __GNUC__ */

static void host_queue_single_thread_test()
{
    oe_lockless_queue queue;
    oe_lockless_queue_node nodes[TEST_COUNT];
    oe_lockless_queue_node* p_node = NULL;

    printf("<host_queue_single_thread_test>\n");

    oe_lockless_queue_init(&queue);

    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        oe_lockless_queue_node_init(nodes + i);
    }

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        oe_lockless_queue_push_back(&queue, nodes + i);
    }

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        p_node = oe_lockless_queue_pop_front(&queue);
        OE_TEST(p_node == nodes + i);
    }

    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</host_queue_single_thread_test>\n");
} /* host_queue_single_thread_test */

static void test_node_init(test_node* p_node)
{
    oe_lockless_queue_node_init(&(p_node->_node));
    p_node->count = 0;
    p_node->pop_order = 0;
} /* test_node_init */

typedef struct _thread_data
{
    oe_lockless_queue* p_queue;
    test_node* p_nodes;
    size_t* p_barrier;
    THREAD_TYPE thread;
    oe_enclave_t* enclave;
} thread_data;

THREAD_RETURN_TYPE host_writer_thread(THREAD_ARG_TYPE _data)
{
    size_t barrier_count;
    thread_data* data = (thread_data*)_data;

    printf("    host_writer_thread started\n");

    /* wait for all threads to start */
#ifdef _MSC_VER
    barrier_count = _InterlockedIncrement64(data->p_barrier);
    while (barrier_count < THREAD_COUNT)
    {
        barrier_count = _InterlockedCompareExchange64(data->p_barrier, 0, 0);
    }
#elif defined __GNUC__
    barrier_count = __atomic_add_fetch(data->p_barrier, 1, __ATOMIC_ACQ_REL);
    while (barrier_count < THREAD_COUNT)
    {
        barrier_count = __atomic_load_n(data->p_barrier, __ATOMIC_ACQUIRE);
    }
#endif /* _MSC_VER or __GNUC__ */

    /* push this thread's nodes onto the queue */
    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        oe_lockless_queue_push_back(
            data->p_queue, (&(data->p_nodes + i)->_node));
    }

    printf("    host_writer_thread finished\n");

    return THREAD_RETURN_VAL;
} /* host_writer_thread */

THREAD_RETURN_TYPE host_reader_thread(THREAD_ARG_TYPE _data)
{
    oe_lockless_queue* p_queue = (oe_lockless_queue*)_data;
    size_t node_count = 0;

    printf("    host_reader_thread - started\n");

    /* pop the nodes off of the queue */
    while (node_count < TEST_COUNT * THREAD_COUNT)
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
    printf("    host_reader_thread - finished\n");
    return THREAD_RETURN_VAL;
} /* host_reader_thread */

THREAD_RETURN_TYPE enc_writer_thread_wrapper(THREAD_ARG_TYPE _data)
{
    OE_UNUSED(_data);
    thread_data* data = (thread_data*)_data;

    printf("    enc_writer_thread - started\n");
    OE_TEST(
        OE_OK ==
        enc_writer_thread(
            data->enclave, data->p_queue, data->p_nodes, data->p_barrier));
    printf("    enc_writer_thread - finished\n");
    return THREAD_RETURN_VAL;
} /* enc_writer_thread */

THREAD_RETURN_TYPE enc_reader_thread_wrapper(THREAD_ARG_TYPE _data)
{
    thread_data* data = (thread_data*)_data;
    printf("    enc_reader_thread started\n");
    OE_TEST(
        OE_OK ==
        enc_pop_nodes(data->enclave, data->p_queue, TEST_COUNT * THREAD_COUNT));
    printf("    enc_reader_thread finished\n");
    return THREAD_RETURN_VAL;
} /* host_reader_thread */

static void host_queue_multi_thread_test()
{
    size_t barrier = 0;
    thread_data threads[THREAD_COUNT];
    test_node nodes[THREAD_COUNT * TEST_COUNT];
    THREAD_TYPE reader;
    oe_lockless_queue queue;

    printf("<host_queue_multi_thread_test>\n");

    oe_lockless_queue_init(&queue);
    for (size_t i = 0; i < THREAD_COUNT * TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    OE_TEST(0 == thread_create(&reader, host_reader_thread, &queue));

    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        threads[i].p_barrier = &barrier;
        threads[i].p_nodes = nodes + i * TEST_COUNT;
        threads[i].p_queue = &queue;
        threads[i].enclave = NULL;
        OE_TEST(
            0 == thread_create(
                     &(threads[i].thread), host_writer_thread, threads + i));
    }

    thread_join(reader);
    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        size_t last_pop_order = 0;
        thread_join(threads[i].thread);
        OE_TEST(1 == nodes[TEST_COUNT * i].count);
        last_pop_order = nodes[TEST_COUNT * i].pop_order;
        for (size_t j = 1; j < TEST_COUNT; ++j)
        {
            OE_TEST(1 == nodes[TEST_COUNT * i + j].count);
            OE_TEST(last_pop_order <= nodes[TEST_COUNT * i + j].pop_order);
            last_pop_order = nodes[TEST_COUNT * i + j].pop_order;
        }
    }
    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</host_queue_multi_thread_test>\n");
} /* host_queue_multi_thread_test */

static void enc_queue_single_thread_test(oe_enclave_t* enclave)
{
    printf("<enc_queue_single_thread_test>\n");

    OE_TEST(OE_OK == enc_test_queue_single_threaded(enclave));

    printf("</enc_queue_single_thread_test>\n");
} /* enc_queue_single_thread_test */

static void enc_queue_multi_thread_test(oe_enclave_t* enclave)
{
    size_t barrier = 0;
    thread_data threads[THREAD_COUNT];
    test_node nodes[THREAD_COUNT * TEST_COUNT];
    oe_lockless_queue queue;
    thread_data reader_thread;

    printf("<enc_queue_multi_thread_test>\n");

    oe_lockless_queue_init(&queue);
    for (size_t i = 0; i < THREAD_COUNT * TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    reader_thread.enclave = enclave;
    reader_thread.p_queue = &queue;

    OE_TEST(
        0 == thread_create(
                 &(reader_thread.thread),
                 enc_reader_thread_wrapper,
                 &reader_thread));

    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        threads[i].p_barrier = &barrier;
        threads[i].p_nodes = nodes + i * TEST_COUNT;
        threads[i].p_queue = &queue;
        threads[i].enclave = enclave;
        OE_TEST(
            0 ==
            thread_create(
                &(threads[i].thread), enc_writer_thread_wrapper, threads + i));
    }

    thread_join(reader_thread.thread);
    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        size_t last_pop_order = 0;
        thread_join(threads[i].thread);
        OE_TEST(1 == nodes[TEST_COUNT * i].count);
        last_pop_order = nodes[TEST_COUNT * i].pop_order;
        for (size_t j = 1; j < TEST_COUNT; ++j)
        {
            OE_TEST(1 == nodes[TEST_COUNT * i + j].count);
            OE_TEST(last_pop_order <= nodes[TEST_COUNT * i + j].pop_order);
            last_pop_order = nodes[TEST_COUNT * i + j].pop_order;
        }
    }
    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</enc_queue_multi_thread_test>\n");
} /*enc_queue_multi_thread_test */

static void host_enq_enc_deq_single_thread_test(oe_enclave_t* enclave)
{
    oe_lockless_queue queue;
    test_node nodes[TEST_COUNT];

    printf("<host_enq_enc_deq_single_thread_test>\n");

    oe_lockless_queue_init(&queue);

    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        oe_lockless_queue_push_back(
            &queue, (oe_lockless_queue_node*)&(nodes[i]._node));
    }

    OE_TEST(OE_OK == enc_pop_nodes(enclave, &queue, TEST_COUNT));

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        OE_TEST(1 == nodes[i].count);
        OE_TEST(i == nodes[i].pop_order);
    }

    printf("<host_enq_enc_deq_single_thread_test>\n");
} /* host_enq_enc_deq_single_thread_test */

static void host_enq_enc_deq_multi_thread_test(oe_enclave_t* enclave)
{
    size_t barrier = 0;
    thread_data threads[THREAD_COUNT];
    test_node nodes[THREAD_COUNT * TEST_COUNT];
    oe_lockless_queue queue;
    thread_data reader_thread;

    printf("<host_enq_enc_deq_multi_thread_test>\n");

    oe_lockless_queue_init(&queue);
    for (size_t i = 0; i < THREAD_COUNT * TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    reader_thread.enclave = enclave;
    reader_thread.p_queue = &queue;

    OE_TEST(
        0 == thread_create(
                 &(reader_thread.thread),
                 enc_reader_thread_wrapper,
                 &reader_thread));

    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        threads[i].p_barrier = &barrier;
        threads[i].p_nodes = nodes + i * TEST_COUNT;
        threads[i].p_queue = &queue;
        threads[i].enclave = NULL;
        OE_TEST(
            0 == thread_create(
                     &(threads[i].thread), host_writer_thread, threads + i));
    }

    thread_join(reader_thread.thread);
    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        size_t last_pop_order = 0;
        thread_join(threads[i].thread);
        OE_TEST(1 == nodes[TEST_COUNT * i].count);
        last_pop_order = nodes[TEST_COUNT * i].pop_order;
        for (size_t j = 1; j < TEST_COUNT; ++j)
        {
            OE_TEST(1 == nodes[TEST_COUNT * i + j].count);
            OE_TEST(last_pop_order <= nodes[TEST_COUNT * i + j].pop_order);
            last_pop_order = nodes[TEST_COUNT * i + j].pop_order;
        }
    }
    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</host_enq_enc_deq_multi_thread_test>\n");
} /* host_enq_enc_deq_multi_thread_test */

static void enc_enq_host_deq_single_thread_test(oe_enclave_t* enclave)
{
    test_node nodes[TEST_COUNT];
    oe_lockless_queue queue;
    test_node* p_node = NULL;

    printf("<enc_enq_host_deq_single_thread_test>\n");

    oe_lockless_queue_init(&queue);
    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    OE_TEST(OE_OK == enc_push_nodes(enclave, &queue, nodes, TEST_COUNT));

    for (size_t i = 0; i < TEST_COUNT; ++i)
    {
        p_node = (test_node*)oe_lockless_queue_pop_front(&queue);
        OE_TEST(p_node == nodes + i);
    }

    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</enc_enq_host_deq_single_thread_test>\n");
} /* enc_enq_host_deq_single_thread_test */

static void enc_enq_host_deq_multi_thread_test(oe_enclave_t* enclave)
{
    size_t barrier = 0;
    thread_data threads[THREAD_COUNT];
    test_node nodes[THREAD_COUNT * TEST_COUNT];
    THREAD_TYPE reader_thread;
    oe_lockless_queue queue;

    printf("<enc_enq_host_deq_multi_thread_test>\n");

    oe_lockless_queue_init(&queue);
    for (size_t i = 0; i < THREAD_COUNT * TEST_COUNT; ++i)
    {
        test_node_init(nodes + i);
    }

    OE_TEST(0 == thread_create(&reader_thread, host_reader_thread, &queue));

    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        threads[i].p_barrier = &barrier;
        threads[i].p_nodes = nodes + i * TEST_COUNT;
        threads[i].p_queue = &queue;
        threads[i].enclave = enclave;
        OE_TEST(
            0 ==
            thread_create(
                &(threads[i].thread), enc_writer_thread_wrapper, threads + i));
    }

    thread_join(reader_thread);
    for (size_t i = 0; i < THREAD_COUNT; ++i)
    {
        size_t last_pop_order = 0;
        thread_join(threads[i].thread);
        OE_TEST(1 == nodes[TEST_COUNT * i].count);
        last_pop_order = nodes[TEST_COUNT * i].pop_order;
        for (size_t j = 1; j < TEST_COUNT; ++j)
        {
            OE_TEST(1 == nodes[TEST_COUNT * i + j].count);
            OE_TEST(last_pop_order <= nodes[TEST_COUNT * i + j].pop_order);
            last_pop_order = nodes[TEST_COUNT * i + j].pop_order;
        }
    }
    OE_TEST(NULL == oe_lockless_queue_pop_front(&queue));

    printf("</enc_enq_host_deq_multi_thread_test>\n");
} /* enc_enq_host_deq_multi_thread_test */

int main(int argc, const char** argv)
{
    oe_result_t result = OE_OK;
    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    /* these tests are executed within the host */
    host_queue_single_thread_test();
    host_queue_multi_thread_test();

    result = oe_create_lockless_queue_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (OE_OK != result)
    {
        oe_put_err("oe_create_lockless_queue_enclave(): result=%u", result);
    }

    /* these tests are executed within the enclave */
    enc_queue_single_thread_test(enclave);
    enc_queue_multi_thread_test(enclave);

    /* these tests enqueue nodes from the host and dequeue nodes from the
     * enclave */
    host_enq_enc_deq_single_thread_test(enclave);
    host_enq_enc_deq_multi_thread_test(enclave);

    /* these tests enqueue nodes from the enclave and dequeue nodes from the
     * host */
    enc_enq_host_deq_single_thread_test(enclave);
    enc_enq_host_deq_multi_thread_test(enclave);

    oe_terminate_enclave(enclave);

    return 0;
}
