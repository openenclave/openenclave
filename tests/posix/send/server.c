// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "server.h"
#if defined(WINDOWS_HOST)
#pragma warning(disable : 4005)
#include <windows.h>
typedef int socklen_t;

static void sleep(int n) { Sleep(n*1000); }
typedef SOCKET socket_t;
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
typedef int socket_t;
#endif
#include <openenclave/internal/tests.h>


void oe_abort(void);

void run_server(uint16_t port)
{
    socket_t listen_sd;
    socket_t client_sd;
    char buf[1024];
    bool quit = false;

#if defined(WINDOWS_HOST)
    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2,2), &wsadata);
#endif

    /* Create the listener socket. */
    if ((listen_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, opt_len) != 0)
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
#if defined(WINDOWS_HOST)
            int tmp = WSAGetLastError();
#else
            int tmp = errno;
#endif
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
#if defined(WINDOWS_HOST)
            if ((n = recv(client_sd, buf, sizeof(buf), 0)) < 0)
#else
            if ((n = read(client_sd, buf, sizeof(buf))) < 0)
#endif
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

#if defined(WINDOWS_HOST)
                if (send(client_sd, buf, (int)n, 0) != n)
#else
                if (write(client_sd, buf, (size_t)n) != n)
#endif
                {
                    OE_TEST("write() failed" == NULL);
                }
            }
        }
    }

    sleep(1);

#if defined(WINDOWS_HOST)
    if (!CloseHandle((HANDLE)client_sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }

    if (!CloseHandle((HANDLE)listen_sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }
#else
    if (close(client_sd) != 0)
    {
        OE_TEST("close() failed" == NULL);
    }

    if (close(listen_sd) != 0)
    {
        OE_TEST("close() failed" == NULL);
    }
#endif
}
