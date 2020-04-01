// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <inttypes.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../../host/hostthread.h"
#include "../../../host/strings.h"
#include "switchless_u.h"

// Increase this number to have a meaningful performance measurement
#define NUM_OCALLS (100000)
#define NUM_ECALLS (100000)

#define STRING_LEN 100
#define STRING_HELLO "Hello World"
#define ENCLAVE_PARAM_STRING "enclave string parameter"
#define ENCLAVE_STACK_STRING "enclave string on stack"

#if defined(__linux__)

double get_relative_time_in_microseconds()
{
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    return (double)current_time.tv_sec * 1000000 +
           (double)current_time.tv_nsec / 1000.0;
}

#elif defined(_WIN32)

#include <Windows.h>

static double frequency;
double get_relative_time_in_microseconds()
{
    LARGE_INTEGER current_time;
    QueryPerformanceCounter(&current_time);
    return current_time.QuadPart / frequency;
}

#endif

int host_echo_switchless(
    const char* in,
    char* out,
    const char* str1,
    char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "host string parameter") == 0);
    OE_TEST(strcmp(str2, "host string on stack") == 0);

    strcpy_s(out, STRING_LEN, in);

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

    strcpy_s(out, STRING_LEN, in);

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
        enc_test_echo_switchless(
            enclave, &return_val, "Hello World", out, NUM_OCALLS) == OE_OK);
    OE_TEST(return_val == 0);
    end = get_relative_time_in_microseconds();
    switchless_microseconds += end - start;

    printf(
        "%d switchless ocalls took %d msecs.\n",
        NUM_OCALLS,
        (int)(switchless_microseconds / 1000.0));

    return switchless_microseconds;
}

typedef struct
{
    oe_thread_t tid;
    oe_enclave_t* enclave;
    double elapsed;
} thread_info_t;

void* launch_enclave_thread(void* a)
{
    thread_info_t* info = (thread_info_t*)a;
    info->elapsed = make_repeated_switchless_ocalls(info->enclave);
    return NULL;
}

void test_switchless_ocalls(oe_enclave_t* enclave, uint64_t num_enclave_threads)
{
    // Measure switchless ocall performance.
    uint64_t num_extra_enc_threads = num_enclave_threads - 1;
    thread_info_t tinfo[NUM_TCS];
    for (uint64_t i = 0; i < num_extra_enc_threads; ++i)
    {
        int ret = 0;
        tinfo[i].enclave = enclave;
        if ((ret = oe_thread_create(
                 &tinfo[i].tid, launch_enclave_thread, &tinfo[i])))
        {
            oe_put_err("thread_create(host): ret=%u", ret);
        }
        printf("Launched enclave producer thread %" PRIu64 "\n", i);
    }
    // Launch switchless calls in main thread as well.
    double elapsed = make_repeated_switchless_ocalls(enclave);

    // Wait for launched threads to finish.
    for (uint64_t i = 0; i < num_extra_enc_threads; ++i)
    {
        if (tinfo[i].tid)
            oe_thread_join(tinfo[i].tid);
    }

    // Record min and max elapsed times.
    double switchless_min = elapsed;
    double switchless_max = elapsed;
    for (uint64_t i = 0; i < num_extra_enc_threads; ++i)
    {
        if (tinfo[i].elapsed < switchless_min)
            switchless_min = tinfo[i].elapsed;
        if (tinfo[i].elapsed > switchless_max)
            switchless_max = tinfo[i].elapsed;
    }

    // Measure regular ocall performance.
    printf("Using main enclave thread to make regular ocalls\n");
    double regular_microseconds = 0;
    double start, end;
    char out[STRING_LEN];
    int return_val;
    start = get_relative_time_in_microseconds();

    OE_TEST(
        enc_test_echo_regular(
            enclave, &return_val, "Hello World", out, NUM_OCALLS) == OE_OK);

    end = get_relative_time_in_microseconds();
    regular_microseconds = end - start;

    // Print performance measurements.
    printf(
        "Time spent in %d regular OCALLs : %d milliseconds\n",
        NUM_OCALLS,
        (int)regular_microseconds / 1000);
    printf(
        "Time spent in %d switchless OCALLs (fastest thread) : %d "
        "milliseconds\n",
        NUM_OCALLS,
        (int)switchless_min / 1000);
    printf(
        "Time spent in %d switchless OCALLs (slowest thread) : %d "
        "milliseconds\n",
        NUM_OCALLS,
        (int)switchless_max / 1000);
    printf(
        "Fastest switchless thread speedup factor : %.2f\n",
        (double)regular_microseconds / switchless_min);
    printf(
        "Slowest switchless thread speedup factor : %.2f\n",
        (double)regular_microseconds / switchless_max);
}

int host_test_echo_switchless(
    oe_enclave_t* enclave,
    const char* in,
    char out[STRING_LEN],
    int repeats)
{
    oe_result_t result;

    if (strcmp(in, STRING_HELLO) != 0)
    {
        return -1;
    }

    char stack_allocated_str[STRING_LEN] = ENCLAVE_STACK_STRING;
    int return_val;

    for (int i = 0; i < repeats; i++)
    {
        result = enc_echo_switchless(
            enclave,
            &return_val,
            in,
            out,
            ENCLAVE_PARAM_STRING,
            stack_allocated_str);
        if (result != OE_OK)
        {
            return -1;
        }

        if (return_val != 0)
        {
            return -1;
        }
    }

    printf("Host: Hello from switchless Echo function!\n");

    return 0;
}

int host_test_echo_regular(
    oe_enclave_t* enclave,
    const char* in,
    char out[STRING_LEN],
    int repeats)
{
    oe_result_t result;

    if (strcmp(in, STRING_HELLO) != 0)
    {
        return -1;
    }

    char stack_allocated_str[STRING_LEN] = ENCLAVE_STACK_STRING;
    int return_val;

    for (int i = 0; i < repeats; i++)
    {
        result = enc_echo_regular(
            enclave,
            &return_val,
            in,
            out,
            ENCLAVE_PARAM_STRING,
            stack_allocated_str);
        if (result != OE_OK)
        {
            return -1;
        }

        if (return_val != 0)
        {
            return -1;
        }
    }

    printf("Host: Hello from regular Echo function!\n");

    return 0;
}

double make_repeated_switchless_ecalls(oe_enclave_t* enclave)
{
    char out[STRING_LEN];
    double start, end;

    double switchless_microseconds = 0.0;

    start = get_relative_time_in_microseconds();
    OE_TEST(
        host_test_echo_switchless(enclave, "Hello World", out, NUM_ECALLS) ==
        0);

    end = get_relative_time_in_microseconds();
    switchless_microseconds += end - start;

    printf(
        "%d switchless ecalls took %d msecs.\n",
        NUM_OCALLS,
        (int)(switchless_microseconds / 1000.0));

    return switchless_microseconds;
}

void* launch_host_thread(void* a)
{
    thread_info_t* info = (thread_info_t*)a;
    info->elapsed = make_repeated_switchless_ecalls(info->enclave);
    return NULL;
}

void test_switchless_ecalls(oe_enclave_t* enclave, uint64_t num_host_threads)
{
    // Measure switchless ecall performance.
    uint64_t num_extra_host_threads = num_host_threads - 1;
    thread_info_t tinfo[NUM_TCS];
    for (uint64_t i = 0; i < num_extra_host_threads; ++i)
    {
        int ret = 0;
        tinfo[i].enclave = enclave;
        if ((ret = oe_thread_create(
                 &tinfo[i].tid, launch_host_thread, &tinfo[i])))
        {
            oe_put_err("thread_create(host): ret=%u", ret);
        }
        printf("Launched host producer thread %" PRIu64 "\n", i);
    }
    // Launch switchless calls in main thread as well.
    double elapsed = make_repeated_switchless_ecalls(enclave);

    // Wait for launched threads to finish.
    for (uint64_t i = 0; i < num_extra_host_threads; ++i)
    {
        if (tinfo[i].tid)
            oe_thread_join(tinfo[i].tid);
    }

    // Record min and max elapsed times.
    double switchless_min = elapsed;
    double switchless_max = elapsed;
    for (uint64_t i = 0; i < num_extra_host_threads; ++i)
    {
        if (tinfo[i].elapsed < switchless_min)
            switchless_min = tinfo[i].elapsed;
        if (tinfo[i].elapsed > switchless_max)
            switchless_max = tinfo[i].elapsed;
    }

    // Measure regular ecall performance.
    printf("Using main host thread to make regular ecalls\n");
    double regular_microseconds = 0;
    double start, end;
    char out[STRING_LEN];
    start = get_relative_time_in_microseconds();

    OE_TEST(
        host_test_echo_regular(enclave, "Hello World", out, NUM_ECALLS) == 0);

    end = get_relative_time_in_microseconds();
    regular_microseconds = end - start;

    // Print performance measurements.
    printf(
        "Time spent in %d regular ECALLs : %d milliseconds\n",
        NUM_OCALLS,
        (int)regular_microseconds / 1000);
    printf(
        "Time spent in %d switchless ECALLs (fastest thread) : %d "
        "milliseconds\n",
        NUM_OCALLS,
        (int)switchless_min / 1000);
    printf(
        "Time spent in %d switchless ECALLs (slowest thread) : %d "
        "milliseconds\n",
        NUM_OCALLS,
        (int)switchless_max / 1000);
    printf(
        "Fastest switchless thread speedup factor : %.2f\n",
        (double)regular_microseconds / switchless_min);
    printf(
        "Slowest switchless thread speedup factor : %.2f\n",
        (double)regular_microseconds / switchless_max);
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc < 2)
    {
    print_usage:
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [--host-threads n] [--enclave-threads n] "
            "[--ecalls]\n",
            argv[0]);
        return 1;
    }

    uint64_t num_host_threads = 1;
    uint64_t num_enclave_threads = 2;
    bool test_ecalls = false;

    {
        int i = 2;
        while (i < argc)
        {
            if (strcmp(argv[i], "--host-threads") == 0)
            {
                if (++i == argc)
                    goto print_usage;
                sscanf_s(argv[i], "%" SCNu64, &num_host_threads);
            }
            else if (strcmp(argv[i], "--enclave-threads") == 0)
            {
                if (++i == argc)
                    goto print_usage;
                sscanf_s(argv[i], "%" SCNu64, &num_enclave_threads);
            }
            else if (strcmp(argv[i], "--test-ecalls") == 0)
            {
                test_ecalls = true;
            }
            else
                goto print_usage;

            ++i;
        }
    }

#if defined(__WIN32)
    QueryPerformanceFrequency(&frequency);
    frequency /= 1000000; // convert to microseconds
#endif

    const uint32_t flags = oe_get_create_flags();

    // Enable switchless and configure host
    oe_enclave_setting_context_switchless_t switchless_setting = {0, 0};

    if (test_ecalls)
        switchless_setting.max_enclave_workers = num_enclave_threads;
    else
        switchless_setting.max_host_workers = num_host_threads;

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

    if (test_ecalls)
        test_switchless_ecalls(enclave, num_host_threads);
    else
        test_switchless_ocalls(enclave, num_enclave_threads);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (switchless)\n");

    return 0;
}
