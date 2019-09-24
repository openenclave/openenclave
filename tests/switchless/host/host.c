// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if _MSC_VER
#include <Windows.h>
#endif
#include "../../../host/hostthread.h"
#include "../../../host/strings.h"
#include "switchless_u.h"

// Increase this number to have a meaningful performance measurement
#define NUM_OCALLS (100000)

#define STRING_LEN 100

#if _MSC_VER
static double frequency;
#endif

static int thread_create(oe_thread_t* thread, void* (*func)(void*), void* arg)
{
#if __GNUC__
    return pthread_create(thread, NULL, func, arg);
#elif _MSC_VER
    typedef DWORD (*start_routine_t)(void*);
    start_routine_t start_routine = (start_routine_t)func;
    *thread = (oe_thread_t)CreateThread(NULL, 0, start_routine, arg, 0, NULL);
    return *thread == (oe_thread_t)NULL ? 1 : 0;
#endif
}

static int thread_join(oe_thread_t thread)
{
#if __GNUC__
    return pthread_join(thread, NULL);
#elif _MSC_VER
    HANDLE handle = (HANDLE)thread;
    if (WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0)
    {
        CloseHandle(handle);
        return 0;
    }
    return 1;
#endif
}

double get_relative_time_in_microseconds()
{
#if __GNUC__
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    return (double)current_time.tv_sec * 1000000 +
           (double)current_time.tv_nsec / 1000.0;
#elif _MSC_VER
    double current_time;
    QueryPerformanceCounter(&current_time);
    return current_time / frequency;
#endif
}

int host_echo_switchless(
    const char* in,
    char* out,
    const char* str1,
    char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "host string parameter") == 0);
    OE_TEST(strcmp(str2, "host string on stack") == 0);

    strcpy(out, in);

    return 0;
}

int host_echo_regular(
    const char* in,
    char* out,
    const char* str1,
    char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "host string parameter") == 0);
    OE_TEST(strcmp(str2, "host string on stack") == 0);

    strcpy(out, in);

    return 0;
}

double make_repeated_switchless_ocalls(oe_enclave_t* enclave)
{
    char out[STRING_LEN];
    int return_val;
    double start, end;

    double switchless_microseconds = 0.0;

    start = get_relative_time_in_microseconds();
    OE_TEST(
        enc_echo_switchless(
            enclave, &return_val, "Hello World", out, NUM_OCALLS) == OE_OK);
    OE_TEST(return_val == 0);
    end = get_relative_time_in_microseconds();
    switchless_microseconds += end - start;

    printf(
        "%d switchless calls took %d msecs.\n",
        NUM_OCALLS,
        (int)(switchless_microseconds / 1000.0));
    return switchless_microseconds;
}

void* launch_enclave_thread(void* e)
{
    make_repeated_switchless_ocalls((oe_enclave_t*)e);
    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc < 2)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [num-host-threads] [num-enclave-threads]\n",
            argv[0]);
        return 1;
    }

    uint64_t num_host_threads = 2;
    uint64_t num_enclave_threads = 2;

    if (argc >= 3)
    {
        sscanf(argv[2], "%lu", &num_host_threads);
    }

    if (argc == 4)
    {
        sscanf(argv[3], "%lu", &num_enclave_threads);
    }

#if _MSC_VER
    QueryPerformanceFrequency(&frequency);
    frequency /= 1000000; // convert to microseconds
#endif

    const uint32_t flags = oe_get_create_flags();

    // Enable switchless and configure host worker number
    oe_enclave_setting_context_switchless_t switchless_setting = {
        num_host_threads, 0};
    oe_enclave_setting_t settings[] = {
        {.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
         .u.context_switchless_setting = &switchless_setting}};

    if ((result = oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    char out[STRING_LEN];
    int return_val;

    uint64_t num_extra_enc_threads = num_enclave_threads - 1;
    oe_thread_t tid[32] = {0};
    for (uint64_t i = 0; i < num_extra_enc_threads; ++i)
    {
        thread_create(&tid[i], launch_enclave_thread, enclave);
        if (tid[i])
        {
            printf("Launched enclave producer thread %ld\n", i);
        }
    }
    printf("Using main enclave thread\n");
    double switchless_microseconds = make_repeated_switchless_ocalls(enclave);

    printf("Making regular ocalls\n");
    double regular_microseconds = 0;
    double start, end;
    start = get_relative_time_in_microseconds();

    OE_TEST(
        enc_echo_regular(
            enclave, &return_val, "Hello World", out, NUM_OCALLS) == OE_OK);

    end = get_relative_time_in_microseconds();
    regular_microseconds = end - start;

    for (uint64_t i = 0; i < num_extra_enc_threads; ++i)
    {
        if (tid[i])
            thread_join(tid[i]);
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf(
        "Time spent in repeating OCALL %d times: switchless %d vs "
        "regular %d ms, speed up: %.2f\n",
        NUM_OCALLS,
        (int)switchless_microseconds / 1000,
        (int)regular_microseconds / 1000,
        (double)regular_microseconds / switchless_microseconds);
    printf("=== passed all tests (switchless)\n");

    return 0;
}
