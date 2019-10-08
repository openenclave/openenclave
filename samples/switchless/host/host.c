// Copyright (c) Microsoft Corporation. All rights reserved.
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

    // Enable switchless and configure host worker number
    oe_enclave_setting_context_switchless_t switchless_setting = {1, 0};
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
        "enclave_add_N_switchless(): %d + %d = %d. Time spent: "
        "%d ms\n",
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
        "enclave_add_N_regular(): %d + %d = %d. Time spent: "
        "%d ms\n",
        oldm,
        n,
        m,
        (int)(end - start) / 1000);

done:
    ret = result != OE_OK ? 1 : 0;
    oe_terminate_enclave(enclave);

    return ret;
}
