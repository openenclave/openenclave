// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "client.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#if defined(WINDOWS_HOST)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <openenclave/internal/tests.h>

void oe_abort();

void run_client(uint16_t port)
{
    socket_t sd;
    const char hello[] = "hello";
    const char quit[] = "quit";
    char buf[1024];

    socket_startup();

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
    if (send(sd, quit, sizeof(quit), 0) != sizeof(quit))
    {
        OE_TEST("write() failed" == NULL);
    }

    socket_close(sd);

    socket_cleanup();
}
