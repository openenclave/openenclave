// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(WINDOWS_HOST)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "server.h"

void oe_abort();

void run_server(uint16_t port)
{
    socket_t listen_sd;
    socket_t client_sd;
    char buf[1024];
    bool quit = false;

    socket_startup();

    /* Create the listener socket. */
    if ((listen_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(
                listen_sd,
                SOL_SOCKET,
                SO_REUSEADDR,
                (const char*)&opt,
                opt_len) != 0)
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
            printf("bind failed: %d\n", get_error());
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
            if ((n = recv(client_sd, buf, sizeof(buf), 0)) < 0)
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

                if (send(client_sd, buf, (length_t)n, 0) != n)
                {
                    OE_TEST("write() failed" == NULL);
                }
            }
        }
    }

    sleep(1);

    socket_close(client_sd);
    socket_close(listen_sd);

    socket_cleanup();
}
