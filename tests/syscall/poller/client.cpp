// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "client.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <openenclave/internal/tests.h>

extern "C" void oe_abort();

void run_client(uint16_t port)
{
    socket_t sd;
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char buf[1024];
    const size_t N = 10;

    sock_startup();

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

    /* write/read "alphabet" to/from  the server. */
    for (size_t i = 0; i < N; i++)
    {
        if (send(sd, alphabet, sizeof(alphabet), 0) != sizeof(alphabet))
        {
            OE_TEST("write() failed" == NULL);
        }

        /* Read "alphabet" from the server. */
        if (recv(sd, buf, sizeof(buf), 0) != sizeof(alphabet))
        {
            OE_TEST("read() failed" == NULL);
        }

        if (memcmp(alphabet, buf, sizeof(alphabet)) != 0)
        {
            OE_TEST("memcmp() failed" == NULL);
        }
    }

    sock_close(sd);

    sock_cleanup();
}
