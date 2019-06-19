// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <../host/hostthread.h>
#include <../host/switchless_manager.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "switchless_u.h"

#ifdef _MSC_VER

#include <Windows.h>

typedef LARGE_INTEGER oe_timer_t;

static void get_time(oe_timer_t* p_time)
{
    QueryPerformanceCounter(p_time);
} /* get_time */

static oe_timer_t elapsed(oe_timer_t start, oe_timer_t stop)
{
    LARGE_INTEGER rval;
    rval.QuadPart = stop.QuadPart - start.QuadPart;
    return rval;
} /* elapsed */

static double timespan_to_sec(oe_timer_t ts)
{
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return (double)ts.QuadPart / (double)freq.QuadPart;
} /* timespan_to_sec */

#elif defined __GNUC__

static long NS_PER_SEC = 1000000000;

typedef struct timespec oe_timer_t;

static void get_time(oe_timer_t* p_time)
{
    clock_gettime(CLOCK_REALTIME, p_time);
} /* get_time */

static oe_timer_t elapsed(oe_timer_t start, oe_timer_t stop)
{
    oe_timer_t rval = {0, 0};
    if (start.tv_nsec > stop.tv_nsec)
    {
        rval.tv_sec = stop.tv_sec - (start.tv_sec + 1);
        rval.tv_nsec = NS_PER_SEC + stop.tv_nsec - start.tv_nsec;
    }
    else
    {
        rval.tv_sec = stop.tv_sec - start.tv_sec;
        rval.tv_nsec = stop.tv_nsec - start.tv_nsec;
    }
    return rval;
} /* elapsed */

static double timespan_to_sec(oe_timer_t ts)
{
    return (double)ts.tv_nsec / (double)NS_PER_SEC + (double)ts.tv_sec;
} /* timespan_to_sec */

#endif /*_MSC_VER or __GNUC__ */

enum
{
    SAMPLE_SIZE = 2048
};

static int generate_random_number()
{
    return rand() % (INT_MAX / 2);
} /* generate_random_number */

static double test_standard_enc_sum(oe_enclave_t* enclave)
{
    oe_timer_t start, stop;
    addition_args* args =
        (addition_args*)malloc(sizeof(addition_args) * SAMPLE_SIZE);

    /* generate sample data */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        args[i].arg1 = generate_random_number();
        args[i].arg2 = generate_random_number();
        args[i].sum = 0;
    }

    /* record start time */
    get_time(&start);

    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        OE_TEST(
            OE_OK == standard_enc_sum(
                         enclave, &(args[i].sum), args[i].arg1, args[i].arg2));
    }

    /* record stop time */
    get_time(&stop);

    /* verify results */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        OE_TEST(args[i].arg1 + args[i].arg2 == args[i].sum);
    }

    free(args);

    return timespan_to_sec(elapsed(start, stop));
} /* test_standard_enc_sum */

static double test_synchronous_switchless_enc_sum(oe_enclave_t* enclave)
{
    oe_timer_t start, stop;
    addition_args* args =
        (addition_args*)malloc(sizeof(addition_args) * SAMPLE_SIZE);

    /* generate sample data */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        args[i].arg1 = generate_random_number();
        args[i].arg2 = generate_random_number();
        args[i].sum = 0;
    }

    /* explicitly start the enclave worker thread */
    oe_switchless_manager_startup(enclave);

    /* record start time */
    get_time(&start);

    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        OE_TEST(
            OE_OK == synchronous_switchless_enc_sum(
                         enclave, &(args[i].sum), args[i].arg1, args[i].arg2));
    }

    /* record stop time */
    get_time(&stop);

    /* verify results */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        OE_TEST(args[i].arg1 + args[i].arg2 == args[i].sum);
    }

    free(args);
    return timespan_to_sec(elapsed(start, stop));
} /* test_synchronous_switchless_enc_sum */

static double test_batch_enc_sum(oe_enclave_t* enclave)
{
    oe_timer_t start, stop;
    addition_args* args =
        (addition_args*)malloc(sizeof(addition_args) * SAMPLE_SIZE);

    /* generate sample data */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        args[i].arg1 = generate_random_number();
        args[i].arg2 = generate_random_number();
        args[i].sum = 0;
    }

    /* record start time */
    get_time(&start);

    OE_TEST(OE_OK == batch_enc_sum(enclave, args, SAMPLE_SIZE));

    /* record stop time */
    get_time(&stop);

    /* verify results */
    for (size_t i = 0; i < SAMPLE_SIZE; ++i)
    {
        OE_TEST(args[i].arg1 + args[i].arg2 == args[i].sum);
    }

    free(args);
    return timespan_to_sec(elapsed(start, stop));
} /* test_batch_enc_sum */

/* this controls the number of threads to use for contentious startup */
#define THREAD_COUNT 20
/* this controls the number of times to run the contentious startup test
 * this test requires creation and termination of the enclave each attempt and
 * requires a long time to run */
#ifdef _MSC_VER
#define ATTEMPTS_AT_CONTENTION 20
#elif defined __GNUC__
#define ATTEMPTS_AT_CONTENTION 100
#endif /* _MSC_VER or __GNUC__ */

typedef struct _contentious_thread_data
{
    oe_enclave_t* enclave;
    size_t* p_barrier;
    size_t thread_count;
} contentious_thread_data_t;

oe_thread_return_t contentious_startup_thread(oe_thread_arg_t _data)
{
    contentious_thread_data_t* data = (contentious_thread_data_t*)_data;
    int arg1 = generate_random_number();
    int arg2 = generate_random_number();
    int sum = 0;
    size_t barrier_count = 0;

    /* wait for all threads to start */
#ifdef _MSC_VER
    barrier_count = _InterlockedIncrement64(data->p_barrier);
    while (barrier_count < data->thread_count)
    {
        barrier_count = _InterlockedCompareExchange64(data->p_barrier, 0, 0);
    }
#elif defined __GNUC__
    barrier_count = __atomic_add_fetch(data->p_barrier, 1, __ATOMIC_ACQ_REL);
    while (barrier_count < data->thread_count)
    {
        barrier_count = __atomic_load_n(data->p_barrier, __ATOMIC_ACQUIRE);
    }
#endif /* _MSC_VER or __GNUC__ */

    OE_TEST(
        OE_OK ==
        synchronous_switchless_enc_sum(data->enclave, &sum, arg1, arg2));
    OE_TEST(arg1 + arg2 == sum);

    return OE_THREAD_RETURN_VAL;
} /* contentious_startup_thread */

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    double standard_sec, switchless_sec, batch_sec;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = oe_create_switchless_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (OE_OK != result)
    {
        oe_put_err("oe_create_switchless_enclave(): result=%u", result);
    }

    standard_sec = test_standard_enc_sum(enclave);
    printf("standard ecall elapsed:   %.8lf\n", standard_sec);

    switchless_sec = test_synchronous_switchless_enc_sum(enclave);
    printf(
        "switchless ecall elapsed: %.8lf (%2.2lf%%)\n",
        switchless_sec,
        100.0 * switchless_sec / standard_sec);

    batch_sec = test_batch_enc_sum(enclave);
    printf(
        "batch ecall elapsed:      %.8lf (%2.2lf%%)\n",
        batch_sec,
        100.0 * batch_sec / standard_sec);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    for (size_t i = 0; i < ATTEMPTS_AT_CONTENTION; ++i)
    {
        /* 1. create an enclave
         * 2. create a number of threads that are controlled by a barrier count
         *    the barrier count is used to ensure that all of the threads are
         *    running prior to the contentious startup call
         *    each worker thread will increment the barrier count and will spin
         *    while waiting for the count to reach the number of threads which
         *    will increase the likelihood of concurrent calls to
         *    oe_switchless_manager_startup
         * 3. all of the threads will execute a switchless call
         * 4. all threads are joined
         * 5. the enclave is terminated */
        contentious_thread_data_t data;
        size_t barrier = 0;

        data.p_barrier = &barrier;
        data.thread_count = THREAD_COUNT;

        result = oe_create_switchless_enclave(
            argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &(data.enclave));
        if (OE_OK != result)
        {
            oe_put_err(
                "oe_create_switchless_enclave returned: %u(%s)",
                result,
                oe_result_str(result));
        }

        oe_thread_t threads[THREAD_COUNT];

        for (size_t j = 0; j < THREAD_COUNT; ++j)
        {
            OE_TEST(
                0 == oe_thread_create(
                         threads + j, contentious_startup_thread, &data));
        }

        for (size_t j = 0; j < THREAD_COUNT; ++j)
        {
            oe_thread_join(threads[j]);
        }

        result = oe_terminate_enclave(data.enclave);
        OE_TEST(result == OE_OK);
    }

    printf("=== passed all tests (switchless)\n");

    return 0;
}
