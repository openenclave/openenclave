// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "echod_u.h"

static const uint16_t PORT = 12345;
static oe_enclave_t* _enclave;

static void* _client_thread_start_routine(void* arg)
{
    int sd;
    const char hello[] = "hello";
    const char quit[] = "quit";
    char buf[1024];

    OE_UNUSED(arg);

    /* Create the client socket. */
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Connect to the server. */
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(PORT);

        if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            OE_TEST("connect() failed" == NULL);
        }
    }

    /* write/read "hello" to/from  the server. */
    {
        if (send(sd, hello, sizeof(hello), 0) != sizeof(hello))
        {
            OE_TEST("write() failed" == NULL);
        }

        /* Read "hello" from the server. */
        if (recv(sd, buf, sizeof(buf), 0) != sizeof(hello))
        {
            OE_TEST("read() failed" == NULL);
        }

        if (memcmp(hello, buf, sizeof(hello)) != 0)
        {
            OE_TEST("memcmp() failed" == NULL);
        }
    }

    /* Send "quit" command to the server. */
    if (write(sd, quit, sizeof(quit)) != sizeof(quit))
    {
        OE_TEST("write() failed" == NULL);
    }

    close(sd);

    return NULL;
}

static void* _server_thread_start_routine(void* arg)
{
    OE_UNUSED(arg);

    echod_run_server_ecall(_enclave, PORT);

    return NULL;
}

void run_server_and_clients(void)
{
    pthread_t client;
    pthread_t server;
    void* ret;

    if (pthread_create(&server, NULL, _server_thread_start_routine, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }

    sleep(1);

    if (pthread_create(&client, NULL, _client_thread_start_routine, NULL) != 0)
    {
        OE_TEST("pthread_create()" == NULL);
    }

    pthread_join(client, &ret);
    pthread_join(server, &ret);
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

    r = oe_create_echod_enclave(argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(r == OE_OK);

    /* Initialize the enclave. */
    r = echod_initialize_ecall(_enclave);
    OE_TEST(r == OE_OK);

    /* Run the clients (host) and the server (enclave). */
    run_server_and_clients();

    /* Terminate the enclave. */
    r = oe_terminate_enclave(_enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (hostfs)\n");

    return 0;
}
