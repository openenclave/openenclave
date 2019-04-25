// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include "echod_t.h"

typedef enum _event
{
    EVENT_NONE,
    EVENT_ACCEPT,
    EVENT_READ,
    EVENT_WRITE,
} event_t;

typedef struct _client
{
    int sockfd;
} client_t;

void echod_initialize_ecall(void)
{
    OE_TEST(oe_load_module_hostfs() == OE_OK);
    OE_TEST(oe_load_module_hostsock() == OE_OK);
    OE_TEST(oe_load_module_polling() == OE_OK);
}

/* Set the socket to blocking mode. */
static int _set_blocking(int fd, bool blocking)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

void echod_run_server_ecall(uint16_t port)
{
    int listen_sock = -1;
    int client_sock = -1;
    char buf[1024];
    bool quit = false;
    fd_set readfds;
    fd_set writefds;

    /* Create the listener socket. */
    if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Reuse this server address. */
    {
        const int opt = 1;
        const socklen_t opt_len = sizeof(opt);

        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, opt_len) !=
            0)
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

        printf("bind\n");

        if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            int tmp = errno;
            printf("bind failed: %d\n", tmp);
            OE_TEST("bind() failed" == NULL);
        }

        if (listen(listen_sock, backlog) != 0)
        {
            OE_TEST("connect() failed" == NULL);
        }
    }

    /* Initialize the read and write sets. */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    /* Watch for read events on the listener socket. */
    FD_SET((uint32_t)listen_sock, &readfds);

    while (!quit)
    {
        ssize_t n;
        event_t event = EVENT_NONE;

        OE_TEST(_set_blocking(listen_sock, false) == 0);

        /* Wait for an event. */
        for (;;)
        {
            fd_set tmp_readfds;
            fd_set tmp_writefds;
            struct timeval timeout;
            int nfds;

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            memcpy(&tmp_readfds, &readfds, sizeof(tmp_readfds));
            memcpy(&tmp_writefds, &writefds, sizeof(tmp_writefds));

            printf("select\n");
            nfds = select(1, &tmp_readfds, &tmp_writefds, NULL, &timeout);

            printf("selectd nfds = %d\n", nfds);
            if (nfds > 0)
            {
                if (FD_ISSET((uint32_t)listen_sock, &tmp_readfds))
                {
                    event = EVENT_ACCEPT;
                    break;
                }
            }
        }

        switch (event)
        {
            case EVENT_ACCEPT:
            {
                OE_TEST(_set_blocking(listen_sock, true) == 0);

                if ((client_sock = accept(listen_sock, NULL, NULL)) < 0)
                {
                    OE_TEST("accept() failed" == NULL);
                }

#if 0
                _set_blocking(client_sock, false);

                /* Watch for read events on this socket. */
                FD_SET((uint32_t)client_sock, &readfds);
#endif

                OE_TEST(_set_blocking(listen_sock, false) == 0);

                break;
            }
            default:
            {
                OE_TEST(false);
            }
        }

        for (;;)
        {
            printf("read\n");
            if ((n = read(client_sock, buf, sizeof(buf))) < 0)
            {
                OE_TEST("read() failed" == NULL);
            }

            if (n > 0)
            {
                printf("received = %s\n", buf);
                if (strncmp(buf, "quit", 4) == 0)
                {
                    printf("got quit\n");
                    quit = true;
                    break;
                }

                printf("write\n");
                if (write(client_sock, buf, (size_t)n) != n)
                {
                    OE_TEST("write() failed" == NULL);
                }
            }
        }
    }

    sleep(1);

    if (close(client_sock) != 0)
    {
        OE_TEST("close() failed" == NULL);
    }

    if (close(listen_sock) != 0)
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
