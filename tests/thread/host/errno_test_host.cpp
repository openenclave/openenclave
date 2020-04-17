// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <signal.h>
#include <stdio.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include "thread_u.h"

#define ERRNO_TEST_TIMES 10
#define LARGE_ENOUGH_MEMORY_SIZE 1024 * 1024 * 1024
#define NUM_ERRNO_TEST_THREADS 2

static int g_error_num_from_thread1 = 0;
static int g_error_num_from_thread2 = 0;

void* errno_thread1(void* para)
{
    int i = 0;
    int t_errno = 0;
    void* buffer = NULL;
    oe_enclave_t* enclave = (oe_enclave_t*)para;

    for (i = 0; i < ERRNO_TEST_TIMES; i++)
    {
        enc_malloc(enclave, &buffer, LARGE_ENOUGH_MEMORY_SIZE, &t_errno);

        if (ENOMEM != t_errno)
        {
            printf(
                "[errno_thread1]Error check errno, expected %d, got %d.\n",
                ENOMEM,
                t_errno);
            g_error_num_from_thread1 |= 0x8;
        }
    }

    return NULL;
}

void* errno_thread2(void* para)
{
    int i = 0;
    int64_t res = 0;
    int t_errno = 0;
    oe_enclave_t* enclave = (oe_enclave_t*)para;

    for (i = 0; i < ERRNO_TEST_TIMES; i++)
    {
        char num_str[] = "123456789987654321123456789987654321";
        enc_strtol(enclave, &res, num_str, 10, &t_errno);

        if (ERANGE != t_errno)
        {
            printf("[errno_thread2] expected %d, errno %d.\n", ERANGE, t_errno);
            g_error_num_from_thread2 |= 0x40;
        }
    }
    return NULL;
}

void test_errno_multi_threads_sameenclave(oe_enclave_t* enclave)
{
    printf("test_errno_multi_threads_sameenclave Starting\n");

    std::thread threads[NUM_ERRNO_TEST_THREADS];
    for (size_t i = 0; i < NUM_ERRNO_TEST_THREADS; i++)
    {
        if (i & 1)
        {
            threads[i] = std::thread(errno_thread1, enclave);
        }
        else
        {
            threads[i] = std::thread(errno_thread2, enclave);
        }
    }

    for (size_t i = 0; i < NUM_ERRNO_TEST_THREADS; i++)
    {
        threads[i].join();
    }

    OE_TEST(g_error_num_from_thread1 == 0);
    OE_TEST(g_error_num_from_thread2 == 0);

    printf("test_errno_multi_threads_sameenclave Complete\n");
}

void test_errno_multi_threads_diffenclave(
    oe_enclave_t* enclave1,
    oe_enclave_t* enclave2)
{
    printf("test_errno_multi_threads_diffenclave Starting\n");

    g_error_num_from_thread1 = 0;
    g_error_num_from_thread2 = 0;
    std::thread threads[NUM_ERRNO_TEST_THREADS];

    for (size_t i = 0; i < NUM_ERRNO_TEST_THREADS; i++)
    {
        if (i & 1)
        {
            threads[i] = std::thread(errno_thread1, enclave1);
        }
        else
        {
            threads[i] = std::thread(errno_thread2, enclave2);
        }
    }

    for (size_t i = 0; i < NUM_ERRNO_TEST_THREADS; i++)
    {
        threads[i].join();
    }

    OE_TEST(g_error_num_from_thread1 == 0);
    OE_TEST(g_error_num_from_thread2 == 0);

    printf("test_errno_multi_threads_diffenclave Complete\n");
}
