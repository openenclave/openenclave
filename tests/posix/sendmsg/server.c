// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "server.h"
#if defined(WINDOWS_HOST)
#pragma warning(disable : 4005)
#include <windows.h>
#include <winsock2.h>
typedef int socklen_t;

static void sleep(int n)
{
    Sleep(n * 1000);
}
typedef SOCKET socket_t;
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#endif
#include <openenclave/internal/tests.h>

void oe_abort(void);

#if defined(WINDOWS_HOST)
void run_server(uint16_t port)
{
    socket_t listen_sd;
    socket_t client_sd = -1;
    bool quit = false;

    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2, 2), &wsadata);

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
            int tmp = WSAGetLastError();
            printf("bind failed: %d\n", tmp);
            OE_TEST("bind() failed" == NULL);
        }

        if (listen(listen_sd, backlog) != 0)
        {
            int tmp = WSAGetLastError();
            printf("listen failed: %d\n", tmp);
            OE_TEST("listen() failed" == NULL);
        }
    }

    while (!quit)
    {
        DWORD n;

        if ((client_sd = accept(listen_sd, NULL, NULL)) == SOCKET_ERROR)
        {
            int tmp = WSAGetLastError();
            printf("accept failed: %d\n", tmp);
            OE_TEST("accept() failed" == NULL);
        }

        for (;;)
        {
            WSAMSG msg;
            WSABUF iov;
            uint8_t iov_buf[256];
            uint8_t msg_control_buf[256];

            memset(&msg, 0, sizeof(msg));
            iov.buf = iov_buf;
            iov.len = sizeof(WSABUF);

            msg.lpBuffers = &iov;
            msg.dwBufferCount = 1;
            msg.Control.buf = msg_control_buf;
            msg.Control.len = sizeof(msg_control_buf);

            if (WSARecv(
                    client_sd,
                    msg.lpBuffers,
                    msg.dwBufferCount,
                    &n,
                    &msg.dwFlags,
                    NULL,
                    NULL) != 0)
            {
                DWORD err = WSAGetLastError();
                printf("recvmsg failed err = %d\n", err);
                OE_TEST("recvmsg() failed" == NULL);
            }
            iov.len = n;

            if (n > 0)
            {
                if (n > 0 && msg.dwBufferCount == 1)
                {
                    const char* str = (const char*)msg.lpBuffers[0].buf;

                    if (strncmp(str, "quit", msg.lpBuffers[0].len) == 0)
                    {
                        quit = true;
                        break;
                    }
                }

                DWORD bytes_sent = 0;
                if (WSASend(
                        client_sd,
                        msg.lpBuffers,
                        msg.dwBufferCount,
                        &bytes_sent,
                        0,
                        NULL,
                        NULL) != 0)
                {
                    DWORD err = WSAGetLastError();
                    printf("sendmsg failed err = %d\n", err);
                    OE_TEST("sendmsg() failed" == NULL);
                }
            }
        }
    }

    Sleep(1000);

    if (!CloseHandle((HANDLE)client_sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }

    if (!CloseHandle((HANDLE)listen_sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }
}
#else
void run_server(uint16_t port)
{
    socket_t listen_sd;
    socket_t client_sd = -1;
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
            OE_TEST("listen() failed" == NULL);
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
            struct msghdr msg = {0};
            struct iovec iov;
            uint8_t iov_buf[256];
            uint8_t msg_control_buf[256] = {0};

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
                {
                    OE_TEST("sendmsg() failed" == NULL);
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
#endif
