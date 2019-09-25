// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "switchless_u.h"

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

    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH [--simulate]\n", argv[0]);
        return 1;
    }

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    // Enable switchless and configure host worker number
    oe_enclave_config_context_switchless_t config = {1, 0};
    oe_enclave_config_t configs[] = {{
        .config_type = OE_ENCLAVE_CONFIG_CONTEXT_SWITCHLESS,
        .u.context_switchless_config = &config,
    }};

    if ((result = oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             configs,
             OE_COUNTOF(configs),
             &enclave)) != OE_OK)
        fprintf(stderr, "oe_create_enclave(): result=%u", result);

    double start, end;
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    start = current_time.tv_sec * 1000000 + current_time.tv_nsec / 1000.0;

    // Call into the enclave
    result = enclave_add_N_switchless(enclave, &m, n);

    clock_gettime(CLOCK_REALTIME, &current_time);
    end = current_time.tv_sec * 1000000 + current_time.tv_nsec / 1000.0;

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

    clock_gettime(CLOCK_REALTIME, &current_time);
    start = current_time.tv_sec * 1000000 + current_time.tv_nsec / 1000.0;

    // Call into the enclave
    m = oldm;
    result = enclave_add_N_regular(enclave, &m, n);

    clock_gettime(CLOCK_REALTIME, &current_time);
    end = current_time.tv_sec * 1000000 + current_time.tv_nsec / 1000.0;

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
