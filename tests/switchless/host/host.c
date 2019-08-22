// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "switchless_u.h"

#define NUM_HOST_THREADS 16

int host_echo(char* in, char* out, char* str1, char* str2, char str3[100])
{
    OE_TEST(strcmp(str1, "oe_host_strdup1") == 0);
    OE_TEST(strcmp(str2, "oe_host_strdup2") == 0);
    OE_TEST(strcmp(str3, "oe_host_strdup3") == 0);

    strcpy(out, in);

    return 0;
}

void* host_thread(void* arg)
{
    char out[100];
    int return_val;

    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    oe_result_t result = enc_echo(enclave, &return_val, "Hello World", out);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    if (strcmp("Hello World", out) != 0)
        oe_put_err("ecall failed: %s != %s\n", "Hello World", out);

    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_switchless_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    pthread_t threads[NUM_HOST_THREADS];
    for (int i = 0; i < NUM_HOST_THREADS; i++)
    {
        int ret = 0;
        if ((ret = pthread_create(&threads[i], 0, host_thread, enclave)))
        {
            oe_put_err("pthread_create(host): ret=%u", ret);
        }
        else
            printf("created thread %u\n", i);
    }

    for (int i = 0; i < NUM_HOST_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (switchless)\n");

    return 0;
}
