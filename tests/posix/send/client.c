// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "client.h"
#if defined(WINDOWS_HOST)
#pragma warning(disable : 4005)
#include <windows.h>
typedef int socklen_t;
typedef SOCKET socket_t;

static void sleep(int n) { Sleep(n*1000); }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#endif
#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void oe_abort(void);

void run_client(uint16_t port)
{
    socket_t sd;
    const char hello[] = "hello";
    const char quit[] = "quit";
    char buf[1024];

#if defined(WINDOWS_HOST)
    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2,2), &wsadata);
#endif

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
        addr.sin_port = htons(port);

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
#if defined(WINDOWS_HOST)
    if (send(sd, quit, sizeof(quit), 0) != sizeof(quit))
#else
    if (write(sd, quit, sizeof(quit)) != sizeof(quit))
#endif
    {
        OE_TEST("write() failed" == NULL);
    }


#if defined(WINDOWS_HOST)
    if (!CloseHandle((HANDLE)sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }
#else
    close(sd);
#endif
}
