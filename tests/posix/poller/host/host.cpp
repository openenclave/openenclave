// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(_WIN32)
#include "../../platform/windows.h"
#else
#include "../../platform/linux.h"
#endif

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <time.h>
#include "../client.h"
#include "../server.h"
#include "poller_u.h"

static const uint16_t PORT = 12347;
static const size_t NUM_CLIENTS = 16;
static oe_enclave_t* _enclave;

static void sleep_msec(uint64_t msec)
{
    struct timespec ts;

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    nanosleep(&ts, NULL);
}

static void* _run_host_client(void* arg)
{
    OE_UNUSED(arg);
    run_client(PORT);
    return NULL;
}

static void* _run_host_server(void* arg)
{
    OE_UNUSED(arg);
    run_server(PORT, NUM_CLIENTS);
    return NULL;
}

static void* _run_enclave_server(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_server(_enclave, PORT, NUM_CLIENTS);

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
    pthread_t clients[NUM_CLIENTS];
    pthread_t server;
    void* ret;

    if (pthread_create(&server, NULL, server_proc, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }

    sleep_msec(50);

    for (size_t i = 0; i < NUM_CLIENTS; i++)
    {
        if (pthread_create(&clients[i], NULL, client_proc, NULL) != 0)
        {
            OE_TEST("pthread_create()" == NULL);
        }
    }

    for (size_t i = 0; i < NUM_CLIENTS; i++)
        pthread_join(clients[i], &ret);

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

    r = oe_create_poller_enclave(argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(r == OE_OK);

    printf("=== start test_host_to_host()\n");
    fflush(stdout);
    test_host_to_host();

    printf("=== start test_enclave_to_host()\n");
    fflush(stdout);
    test_enclave_to_host();

    printf("=== start test_host_to_enclave()\n");
    fflush(stdout);
    test_host_to_enclave();

    printf("=== start test_enclave_to_enclave()\n");
    fflush(stdout);
    test_enclave_to_enclave();

    r = oe_terminate_enclave(_enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");
    fflush(stdout);

    return 0;
}
