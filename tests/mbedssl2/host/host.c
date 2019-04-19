// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/posix/fs.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "mbedssl2_u.h"

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
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    pthread_t server_thread;
    pthread_t client_thread;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_mbedssl2_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    /* Run the server thread. */
    if (pthread_create(&server_thread, NULL, _server_proc, enclave) != 0)
    {
        OE_TEST("pthread_create() failed" == NULL);
    }

    sleep(1);

    /* Run the client thread. */
    if (pthread_create(&client_thread, NULL, _client_proc, enclave) != 0)
    {
        OE_TEST("pthread_create() failed" == NULL);
    }

    fflush(stdout);
    pthread_join(client_thread, NULL);

    /* Cancel the server thread now that client was successful. */
    pthread_cancel(server_thread);

#if 0
    printf("JOINING SERVER...\n");
    fflush(stdout);
    pthread_join(server_thread, NULL);
#endif

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_mbedssl)\n");

    return 0;
}
