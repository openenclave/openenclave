// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !defined(_MSC_VER)

// Visual C is allergic to gnu pragmas
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#else
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wconversion"
#endif
#endif

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#if defined(_MSC_VER)
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/tests.h>
#include <windows.h>

typedef oe_socklen_t socklen_t;
typedef oe_in_port_t in_port_t;

static void sleep(int secs)
{
    Sleep(secs * 1000);
}

typedef HANDLE pthread_t;
#else
#include <netinet/in.h>
#include <openenclave/internal/tests.h>

#include "socketpair_test_u.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "socketpair_test_u.h"

#define SERVER_PORT "12345"

static char test_data[1024] = {0};
static ssize_t test_data_len = sizeof(test_data);
static oe_enclave_t* _enclave;

static int server_status = 0;
static int client_status = 0;

static void* _run_enclave_server(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_server(_enclave, &server_status);

    return 0;
}

static void* _run_enclave_client(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_client(_enclave, &client_status, test_data, &test_data_len);
    return 0;
}

void run_test()
{
    pthread_t client;
    pthread_t server;
    void* ret;

#if defined(_WIN32)
    server = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)_run_enclave_server, NULL, 0, NULL);
    OE_TEST(server != INVALID_HANDLE_VALUE);
#else
    if (pthread_create(&server, NULL, _run_enclave_server, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }
#endif

    sleep(1);

#if defined(_WIN32)
    client = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)_run_enclave_client, NULL, 0, NULL);
    OE_TEST(client != INVALID_HANDLE_VALUE);
#else
    if (pthread_create(&client, NULL, _run_enclave_client, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }
#endif

#if defined(_WIN32)
    ret = WaitForSingleObject(client, INFINITE);
    ret = WaitForSingleObject(server, INFINITE);
#else
    pthread_join(client, &ret);
    pthread_join(server, &ret);
#endif
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    int retval = 0;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_socketpair_test_enclave(
        argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(r == OE_OK);

    r = init_enclave(_enclave, &retval);
    OE_TEST(r == OE_OK);

    run_test();

    r = oe_terminate_enclave(_enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (sendmsg)\n");

    return 0;
}
