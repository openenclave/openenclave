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

#define STRING_LEN 100

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

    uint64_t num_host_threads = 1;
    uint64_t num_enclave_threads = 2;

    if (argc >= 3)
    {
        sscanf(argv[2], "%" SCNu64, &num_host_threads);
    }

    if (argc == 4)
    {
        sscanf(argv[3], "%" SCNu64, &num_enclave_threads);
        if (num_enclave_threads > NUM_TCS)
        {
            fprintf(
                stderr,
                "Number of enclave threads must be less than %d\n",
                (int)NUM_TCS);
            return 1;
        }
    }

#if defined(__WIN32)
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
        enc_echo_regular(
            enclave, &return_val, "Hello World", out, NUM_OCALLS) == OE_OK);

    end = get_relative_time_in_microseconds();
    regular_microseconds = end - start;

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

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

    printf("=== passed all tests (switchless)\n");

    return 0;
}
