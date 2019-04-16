// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "mbedssl3_u.h"

static void* _server_proc(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    oe_result_t r;

    r = run_server(enclave);
    OE_TEST(r == OE_OK);

    return NULL;
}

static void* _client_proc(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    oe_result_t r;

    r = run_client(enclave);
    OE_TEST(r == OE_OK);

    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* senclave = NULL;
    oe_enclave_t* cenclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    pthread_t server_thread;
    pthread_t client_thread;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_mbedssl3_enclave(argv[1], type, flags, NULL, 0, &senclave);
    OE_TEST(r == OE_OK);

    r = oe_create_mbedssl3_enclave(argv[1], type, flags, NULL, 0, &cenclave);
    OE_TEST(r == OE_OK);

    if (pthread_create(&server_thread, NULL, _server_proc, senclave) != 0)
        OE_TEST("pthread_create() failed" == NULL);

    sleep(1);

    if (pthread_create(&client_thread, NULL, _client_proc, cenclave) != 0)
        OE_TEST("pthread_create() failed" == NULL);

    sleep(10);

    fflush(stdout);
    pthread_join(client_thread, NULL);

    pthread_cancel(server_thread);

    r = oe_terminate_enclave(senclave);
    OE_TEST(r == OE_OK);

    r = oe_terminate_enclave(cenclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_mbedssl)\n");

    return 0;
}
