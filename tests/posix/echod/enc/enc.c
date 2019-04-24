// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "echod_t.h"

void echod_initialize_ecall(void)
{
    OE_TEST(oe_load_module_hostfs() == OE_OK);
    OE_TEST(oe_load_module_hostsock() == OE_OK);
    OE_TEST(oe_load_module_polling() == OE_OK);
}

void echod_run_server_ecall(uint16_t port)
{
    int listen_sd;
    int client_sd;
    char buf[1024];
    bool quit = false;

    /* Create the listener socket. */
    if ((listen_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &opt, opt_len) != 0)
        {
            OE_TEST("setsockopt() failed" == NULL);
        }
    }

    /* Listen on this address. */
    {
        struct sockaddr_in addr;
        const int backlog = 10;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(listen_sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            int tmp = errno;
            printf("bind failed: %d\n", tmp);
            OE_TEST("bind() failed" == NULL);
        }

        if (listen(listen_sd, backlog) != 0)
        {
            OE_TEST("connect() failed" == NULL);
        }
    }

    while (!quit)
    {
        ssize_t n;

        if ((client_sd = accept(listen_sd, NULL, NULL)) < 0)
        {
            OE_TEST("accept() failed" == NULL);
        }

        for (;;)
        {
            if ((n = read(client_sd, buf, sizeof(buf))) < 0)
            {
                OE_TEST("read() failed" == NULL);
            }

            if (n > 0)
            {
                if (strncmp(buf, "quit", 4) == 0)
                {
                    quit = true;
                    break;
                }

                if (write(client_sd, buf, (size_t)n) != n)
                {
                    OE_TEST("write() failed" == NULL);
                }
            }
        }
    }

    sleep(1);

    if (close(client_sd) != 0)
    {
        OE_TEST("close() failed" == NULL);
    }

    if (close(listen_sd) != 0)
    {
        OE_TEST("close() failed" == NULL);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
