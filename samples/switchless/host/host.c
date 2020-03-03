// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "switchless_u.h"

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
    double current_time;
    QueryPerformanceCounter(&current_time);
    return current_time / frequency;
}

#endif

void host_increment_switchless(int* n)
{
    *n = *n + 1;
}

void host_increment_regular(int* n)
{
    *n = *n + 1;
}

static bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stderr, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;
    int ret = 1, m = 1000000, n = 1000000;
    int oldm = m;
    double switchless_microseconds = 0;
    double start, end;

    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH [--simulate]\n", argv[0]);
        return 1;
    }

#if defined(_WIN32)
    QueryPerformanceFrequency(&frequency);
    frequency /= 1000000; // convert to microseconds
#endif

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    // To demonstrate the benefit of using switchless ocalls, we will
    // first make 1000000 switchless ocalls from the main thread and measure
    // the time taken. Then we will make the same number of regular ocalls
    // and measure the time taken. Using the two measurements, we can arrive at
    // the speedup factor that switchless ocalls provide over normal ocalls.
    //
    // Similarly, to demonstrate the benefit of using switchless ecalls, we will
    // first make 1000000 switchless ecalls from the main thread and measure the
    // time taken. Then we will make the same number of regular ecalls and
    // measure the time taken. Using the two measurements, we can arrive at the
    // speedup factor that switchless ecalls provide over normall ecalls.
    //
    // The sample is written in such a manner that at a given time there are
    // effectively only two actively running threads
    //    - a caller thread that is continuously making switchless calls.
    //    - a worker thread that is continuously servicing the switchless calls.
    // On a machine with at least two cores, having just two threads allows each
    // thread to run potentially uninterrupted on a dedicated core. An
    // application where the worker and caller threads can run uninterrupted on
    // dedicated cores will likely see maximum speed up from switchless calls.
    // On a machine with more than two cores, the number of worker and caller
    // threads can be increased while retaining the benefits of switchless
    // calls.
    //
    // Below, we enable switchless calling, and configure 1 host worker thread
    // for servicing switchless ocalls, and 1 enclave worker thread for
    // servicing switchless ecalls. Note: When we are making switchless ocalls,
    // the ecall worker thread will be sleeping. When we are making switchless
    // ecalls, the ocall worker thread will be sleeping. Thus, including the
    // main thread, there will be two active threads at a given time, utilizing
    // the cores uninterrupted.
    oe_enclave_setting_context_switchless_t switchless_setting = {
        1,  // number of host worker threads
        1}; // number of enclave worker threads.
    oe_enclave_setting_t settings[] = {{
        .setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
        .u.context_switchless_setting = &switchless_setting,
    }};

    if ((result = oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             settings,
             OE_COUNTOF(settings),
             &enclave)) != OE_OK)
        fprintf(stderr, "oe_create_enclave(): result=%u", result);

    start = get_relative_time_in_microseconds();

    // Call into the enclave
    result = enclave_add_N_switchless(enclave, &m, n);

    end = get_relative_time_in_microseconds();

    if (result != OE_OK)
    {
        fprintf(stderr, "enclave_add_N_switchless(): result=%u", result);
        goto done;
    }

    fprintf(
        stderr,
        "%d host_increment_switchless() calls: %d + %d = %d. Time spent: "
        "%d ms\n",
        n,
        oldm,
        n,
        m,
        (int)(end - start) / 1000);

    start = get_relative_time_in_microseconds();

    // Call into the enclave
    m = oldm;
    result = enclave_add_N_regular(enclave, &m, n);

    end = get_relative_time_in_microseconds();

    if (result != OE_OK)
    {
        fprintf(stderr, "enclave_add_N_regular(): result=%u", result);
        goto done;
    }

    fprintf(
        stderr,
        "%d host_increment_regular() calls: %d + %d = %d. Time spent: "
        "%d ms\n",
        n,
        oldm,
        n,
        m,
        (int)(end - start) / 1000);

    // Execute n ecalls switchlessly
    start = get_relative_time_in_microseconds();
    m = oldm;
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = enclave_decrement_switchless(enclave, &m);
        if (result != OE_OK)
        {
            fprintf(
                stderr, "enclave_decrement_switchless(): result=%u", result);
        }
    }
    end = get_relative_time_in_microseconds();
    fprintf(
        stderr,
        "%d enclave_decrement_switchless() calls: %d - %d = %d. Time spent: "
        "%d ms\n",
        n,
        oldm,
        n,
        m,
        (int)(end - start) / 1000);

    // Execute n regular ecalls
    start = get_relative_time_in_microseconds();
    m = oldm;
    for (int i = 0; i < n; i++)
    {
        oe_result_t result = enclave_decrement_regular(enclave, &m);
        if (result != OE_OK)
        {
            fprintf(stderr, "enclave_decrement_regular(): result=%u", result);
        }
    }
    end = get_relative_time_in_microseconds();
    fprintf(
        stderr,
        "%d enclave_decrement_regular() calls: %d - %d = %d. Time spent: "
        "%d ms\n",
        n,
        oldm,
        n,
        m,
        (int)(end - start) / 1000);

done:
    ret = result != OE_OK ? 1 : 0;
    oe_terminate_enclave(enclave);

    return ret;
}
