// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#if defined(_MSC_VER)
#define OE_NEED_STD_NAMES
#include <windows.h>
static void sleep(int secs)
{
    Sleep(secs * 1000);
}
typedef HANDLE pthread_t;
#else
#include <pthread.h>
#include <unistd.h>
#endif
#include <stdio.h>
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

#if defined(_WIN32)
printf("p1\n");
    server = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)server_proc, NULL, 0, NULL);
    OE_TEST(server != INVALID_HANDLE_VALUE);
printf("p2\n");
#else
    if (pthread_create(&server, NULL, server_proc, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }
#endif

    sleep(1);

#if defined(_WIN32)
printf("p3\n");
    client = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)client_proc, NULL, 0, NULL);
    OE_TEST(client != INVALID_HANDLE_VALUE);
printf("p4\n");
#else
    if (pthread_create(&client, NULL, client_proc, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }
#endif

#if defined(_WIN32)
    ret = WaitForSingleObject(client, 30000);
    ret = WaitForSingleObject(server, 30000);
#else
    pthread_join(client, &ret);
    pthread_join(server, &ret);
#endif
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

    printf("=== passed all tests (sendmsg)\n");

    return 0;
}
