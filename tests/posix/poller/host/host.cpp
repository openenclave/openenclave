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

typedef struct thread_arg
{
    poller_type_t poller_type;
} server_arg_t;

static void* _run_host_client(void* arg)
{
    OE_UNUSED(arg);
    run_client(PORT);
    return NULL;
}

static void* _run_host_server(void* arg_)
{
    server_arg_t* arg = (server_arg_t*)arg_;

    run_server(PORT, NUM_CLIENTS, arg->poller_type);

    return NULL;
}

static void* _run_enclave_server(void* arg_)
{
    server_arg_t* arg = (server_arg_t*)arg_;

    run_enclave_server(_enclave, PORT, NUM_CLIENTS, arg->poller_type);

    return NULL;
}

static void* _run_enclave_client(void* arg)
{
    OE_UNUSED(arg);

    run_enclave_client(_enclave, PORT);

    return NULL;
}

void run_test(
    void* (*client_proc)(void*),
    void* (*server_proc)(void*),
    poller_type_t poller_type)
{
    thread_t clients[NUM_CLIENTS];
    thread_t server;
    server_arg_t arg = {poller_type};

    if (thread_create(&server, server_proc, &arg) != 0)
    {
        OE_TEST("thread_create()" == NULL);
    }

    sleep_msec(50);

    for (size_t i = 0; i < NUM_CLIENTS; i++)
    {
        if (thread_create(&clients[i], client_proc, NULL) != 0)
        {
            OE_TEST("thread_create()" == NULL);
        }
    }

    for (size_t i = 0; i < NUM_CLIENTS; i++)
        thread_join(clients[i]);

    thread_join(server);
}

void test_host_to_host(poller_type_t poller_type)
{
    printf("=== start %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    run_test(_run_host_client, _run_host_server, poller_type);
    printf("=== passed %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    fflush(stdout);
}

void test_host_to_enclave(poller_type_t poller_type)
{
    printf("=== start %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    run_test(_run_host_client, _run_enclave_server, poller_type);
    printf("=== passed %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    fflush(stdout);
}

void test_enclave_to_host(poller_type_t poller_type)
{
    printf("=== start %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    run_test(_run_enclave_client, _run_host_server, poller_type);
    printf("=== passed %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    fflush(stdout);
}

void test_enclave_to_enclave(poller_type_t poller_type)
{
    printf("=== start %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    run_test(_run_enclave_client, _run_enclave_server, poller_type);
    printf("=== passed %s(): %s\n", __FUNCTION__, poller::name(poller_type));
    fflush(stdout);
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH POLL_TYPE\n", argv[0]);
        return 1;
    }

    r = oe_create_poller_enclave(argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(r == OE_OK);

    const char* poller_type_name = argv[2];
    poller_type_t poller_type;

    if (strcmp(poller_type_name, "select") == 0)
        poller_type = POLLER_TYPE_SELECT;
    else if (strcmp(poller_type_name, "poll") == 0)
        poller_type = POLLER_TYPE_POLL;
    else if (strcmp(poller_type_name, "epoll") == 0)
        poller_type = POLLER_TYPE_EPOLL;
    else
    {
        fprintf(stderr, "Unknown poller type: %s\n", poller_type_name);
        exit(1);
    }

    test_host_to_host(poller_type);
    test_enclave_to_host(poller_type);
    test_host_to_enclave(poller_type);
    test_enclave_to_enclave(poller_type);

    test_fd_set(_enclave);

    r = oe_terminate_enclave(_enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");
    fflush(stdout);

    return 0;
}
