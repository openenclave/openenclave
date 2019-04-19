// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void oe_abort(void);

void run_server(uint16_t port)
{
    int listen_sd;
    int client_sd = -1;
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
            struct msghdr msg;
            struct iovec iov;
            uint8_t iov_buf[256];
            uint8_t msg_control_buf[256];

            memset(&msg, 0, sizeof(msg));
            iov.iov_base = iov_buf;
            iov.iov_len = sizeof(iov_buf);

            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = msg_control_buf;
            msg.msg_controllen = sizeof(msg_control_buf);

            if ((n = recvmsg(client_sd, &msg, 0)) < 0)
                OE_TEST("read() failed" == NULL);

            iov.iov_len = (typeof(iov.iov_len))n;

            if (n > 0)
            {
                if (n > 0 && msg.msg_iovlen == 1)
                {
                    const char* str = (const char*)msg.msg_iov[0].iov_base;

                    if (strncmp(str, "quit", msg.msg_iov[0].iov_len) == 0)
                    {
                        quit = true;
                        break;
                    }
                }

                if (sendmsg(client_sd, &msg, 0) != n)
                    OE_TEST("sendmsg() failed" == NULL);
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
