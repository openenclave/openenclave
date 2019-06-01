// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(WINDOWS_HOST)
#include "../platform/windows.h"
#else
#include "../platform/linux.h"
#endif

#include <openenclave/internal/tests.h>
#include <openenclave/internal/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "poller.h"
#include "server.h"

#define BUFFER_SIZE 13

extern "C" void oe_abort();

socket_t create_listener_socket(uint16_t port)
{
    socket_t ret = INVALID_SOCKET;
    socket_t sock = INVALID_SOCKET;
    const int opt = 1;
    const socklen_t n = sizeof(opt);
    struct sockaddr_in addr;
    const int backlog = 10;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        goto done;

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, n) != 0)
        goto done;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        goto done;

    if (listen(sock, backlog) != 0)
        goto done;

    if (sock_set_blocking(sock, false) != 0)
        goto done;

    ret = sock;
    sock = INVALID_SOCKET;

done:

    if (sock != INVALID_SOCKET)
        sock_close(sock);

    return ret;
}

typedef struct _client
{
    socket_t sock;
    std::vector<uint8_t> out;
} client_t;

client_t* find_client(std::vector<client_t>& clients, socket_t sock)
{
    for (size_t i = 0; i < clients.size(); i++)
    {
        if (clients[i].sock == sock)
            return &clients[i];
    }

    /* Not found */
    return NULL;
}

extern "C" void run_server(
    uint16_t port,
    size_t num_clients,
    poller_type_t poller_type)
{
    socket_t listener;
    bool quit = false;
    std::vector<client_t> clients;
    size_t num_disconnects = 0;
    poller* poller = poller::create(poller_type);

    OE_TEST(poller);

    sock_startup();

    if ((listener = create_listener_socket(port)) == INVALID_SOCKET)
    {
        OE_TEST("create_listener_socket() failed" == NULL);
    }

    /* Watch for read events on the listener socket (i.e., connects). */
    OE_TEST(poller->add(listener, POLLER_READ) == 0);

    while (!quit)
    {
        std::vector<event_t> events;
        client_t* client;

        /* Wait for events. */
        if (poller->wait(events) < 0)
        {
            OE_TEST(false);
            continue;
        }

        OE_TEST(events.size() > 0);

        for (size_t i = 0; i < events.size(); i++)
        {
            const event_t& event = events[i];

            /* Handle client connection. */
            if (event.sock == listener)
            {
                if ((event.events & POLLER_READ))
                {
                    socket_t sock;

                    if (sock_set_blocking(listener, true) != 0)
                        OE_TEST("sock_set_blocking" == NULL);

                    if ((sock = accept(listener, NULL, NULL)) < 0)
                        OE_TEST("accept() failed" == NULL);

                    if (sock_set_blocking(listener, false) != 0)
                        OE_TEST("sock_set_blocking" == NULL);

                    client_t client = {sock};
                    clients.push_back(client);

                    sock_set_blocking(sock, false);
                    OE_TEST(poller->add(sock, POLLER_READ) == 0);

                    printf("client %lld connect\n", OE_LLD((int64_t)sock));
                    fflush(stdout);
                }
                else
                {
                    OE_TEST(false);
                }

                continue;
            }

            /* Find the client for this event. */
            OE_TEST((client = find_client(clients, event.sock)));

            /* Handle client input. */
            if ((event.events & POLLER_READ))
            {
                /* Read until EAGAIN is encountered. */
                for (;;)
                {
                    uint8_t buf[BUFFER_SIZE];
                    ssize_t n;

                    errno = 0;

                    n = sock_recv(client->sock, buf, sizeof(buf), 0);

                    if (n > 0)
                    {
                        printf(
                            "client %lld input: %zd bytes\n",
                            OE_LLD((int64_t)client->sock),
                            n);
                        fflush(stdout);

                        client->out.insert(client->out.end(), buf, buf + n);
                        OE_TEST(poller->add(client->sock, POLLER_WRITE) == 0);
                    }
                    else if (n == 0)
                    {
                        printf(
                            "client %lld disconnect\n",
                            OE_LLD((int64_t)client->sock));
                        fflush(stdout);

                        /* Client disconnect. */
                        OE_TEST(
                            poller->remove(
                                client->sock, POLLER_WRITE | POLLER_READ) == 0);
                        sock_close(client->sock);

                        num_disconnects++;

                        if (num_disconnects == num_clients)
                        {
                            quit = true;
                            break;
                        }

                        break;
                    }
                    else if (test_would_block())
                    {
                        break;
                    }
                    else
                    {
                        OE_TEST(false);
                    }
                }

                if (quit)
                    break;
            }

            /* Handle client input. */
            if ((event.events & POLLER_WRITE))
            {
                /* Write until output is exhausted or EAGAIN encountered. */
                for (;;)
                {
                    std::vector<uint8_t>& out = client->out;
                    ssize_t n;

                    OE_TEST(out.size() > 0);

                    errno = 0;

                    /* Send data to client. */
                    n = sock_send(client->sock, &out[0], out.size(), 0);

                    if (n > 0)
                    {
                        printf(
                            "client %lld output: %zd bytes\n",
                            OE_LLD((int64_t)client->sock),
                            n);
                        fflush(stdout);

                        out.erase(out.begin(), out.begin() + n);

                        if (out.size() == 0)
                        {
                            OE_TEST(
                                poller->remove(event.sock, POLLER_WRITE) == 0);
                            break;
                        }
                    }
                    else if (test_would_block())
                    {
                        break;
                    }
                    else
                    {
                        OE_TEST(false);
                    }
                }
            }

            if ((event.events & POLLER_EXCEPT))
            {
                // OE_TEST("exception" == NULL);
            }
        }
    }

    sock_close(listener);

    sock_cleanup();

    poller::destroy(poller);
}
