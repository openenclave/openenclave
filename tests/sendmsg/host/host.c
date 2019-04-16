// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "../client.h"
#include "../server.h"
#include "sendmsg_u.h"

static const uint16_t PORT = 12347;
static oe_enclave_t* _enclave;

static void* _run_host_client(void* arg)
{
    OE_UNUSED(arg);
    run_client(PORT);
    return NULL;
}

static void* _run_host_server(void* arg)
{
    OE_UNUSED(arg);
    run_server(PORT);
    return NULL;
}

static void* _run_enclave_server(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_server(_enclave, PORT);

    return NULL;
}

static void* _run_enclave_client(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_client(_enclave, PORT);

    return NULL;
}

void run_test(void* (*client_proc)(void*), void* (*server_proc)(void*))
{
    pthread_t client;
    pthread_t server;
    void* ret;

    if (pthread_create(&server, NULL, server_proc, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }

    sleep(1);

    if (pthread_create(&client, NULL, client_proc, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }

    pthread_join(client, &ret);
    pthread_join(server, &ret);
}

void test_host_to_host(void)
{
    run_test(_run_host_client, _run_host_server);
    printf("=== passed %s()\n", __FUNCTION__);
    fflush(stdout);
}

void test_host_to_enclave(void)
{
    run_test(_run_host_client, _run_enclave_server);
    printf("=== passed %s()\n", __FUNCTION__);
    fflush(stdout);
}

void test_enclave_to_host(void)
{
    run_test(_run_enclave_client, _run_host_server);
    printf("=== passed %s()\n", __FUNCTION__);
    fflush(stdout);
}

void test_enclave_to_enclave(void)
{
    run_test(_run_enclave_client, _run_enclave_server);
    printf("=== passed %s()\n", __FUNCTION__);
    fflush(stdout);
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_sendmsg_enclave(argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(r == OE_OK);

    test_host_to_host();
    test_enclave_to_host();
    test_host_to_enclave();
    test_enclave_to_enclave();

    r = oe_terminate_enclave(_enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
