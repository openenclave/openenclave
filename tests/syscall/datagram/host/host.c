// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/syscall/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "test_datagram_u.h"

#if defined(_MSC_VER)
#include "../../platform/windows.h"
#else
#include "../../platform/linux.h"
#endif

static void* _server_thread(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;

    printf("host: %s\n", __FUNCTION__);
    OE_TEST(run_server_ecall(enclave) == OE_OK);

    return NULL;
}

static void* _client_thread(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;

    printf("host: %s\n", __FUNCTION__);
    OE_TEST(run_client_ecall(enclave) == OE_OK);

    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    thread_t server;
    thread_t client;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_test_datagram_enclave(
        argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = init_ecall(enclave);
    OE_TEST(r == OE_OK);

    OE_TEST(thread_create(&server, _server_thread, enclave) == 0);
    sleep_msec(250);
    OE_TEST(thread_create(&client, _client_thread, enclave) == 0);
    OE_TEST(thread_join(server) == 0);
    OE_TEST(thread_join(client) == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (test_datagram)\n");

    return 0;
}
