// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "switchless_u.h"

void host_increment(int* n)
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
    int ret = 1, m = 10000, n = 10000;
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

    // Call into the enclave
    result = enclave_add_N(enclave, &m, n);
    if (result != OE_OK)
        fprintf(stderr, "enclave_add_N(): result=%u", result);

    fprintf(stderr, "enclave_add_N(): %d + %d = %d\n", oldm, n, m);

    ret = result != OE_OK ? 1 : 0;
    oe_terminate_enclave(enclave);

    return ret;
}
