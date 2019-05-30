// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(_WIN32)
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

int set_blocking(socket_t sock, bool blocking)
{
#if defined(WINDOWS_HOST)

    unsigned long flag = blocking ? 0 : 1;

    if (ioctlsocket(sock, FIONBIO, &flag) != 0)
        return -1;

    return 0;
#else

    int flags;

    if ((flags = fcntl(sock, F_GETFL, 0)) == -1)
        return -1;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) == -1)
        return -1;

    return 0;
#endif
}

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

    if (set_blocking(sock, true) != 0)
        goto done;

    ret = sock;
    sock = INVALID_SOCKET;

done:

    if (sock != INVALID_SOCKET)
        socket_close(sock);

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

void run_server(uint16_t port, size_t num_clients)
{
    socket_t listener;
    bool quit = false;
    poller poller;
    std::vector<client_t> clients;
    size_t num_disconnects = 0;

    socket_startup();

    if ((listener = create_listener_socket(port)) == INVALID_SOCKET)
    {
        OE_TEST("create_listener_socket() failed" == NULL);
    }

    /* Watch for read events on the listener socket (i.e., connects). */
    poller.add(listener, POLLER_READ);

    while (!quit)
    {
        std::vector<event_t> events;
        client_t* client;

        /* Wait for events. */
        if (poller.wait(events) < 0)
        {
            OE_TEST(false);
            continue;
        }

        for (size_t i = 0; i < events.size(); i++)
        {
            const event_t& event = events[i];

            /* Handle client connection. */
            if (event.sock == listener)
            {
                if ((event.events & POLLER_READ))
                {
                    socket_t sock;

                    if ((sock = accept(listener, NULL, NULL)) < 0)
                        OE_TEST("accept() failed" == NULL);

                    client_t client = {sock};
                    clients.push_back(client);

                    set_blocking(sock, false);
                    poller.add(sock, POLLER_READ);

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

#if defined(_WIN32)
                    n = recv(client->sock, (char*)buf, sizeof(buf), 0);
#else
                    n = recv(client->sock, buf, sizeof(buf), 0);
#endif

                    if (n > 0)
                    {
                        printf(
                            "client %lld input: %zd bytes\n",
                            OE_LLD((int64_t)client->sock),
                            n);
                        fflush(stdout);

                        client->out.insert(client->out.end(), buf, buf + n);
                        poller.add(client->sock, POLLER_WRITE);
                    }
                    else if (n == 0)
                    {
                        printf(
                            "client %lld disconnect\n",
                            OE_LLD((int64_t)client->sock));
                        fflush(stdout);

                        /* Client disconnect. */
                        poller.remove(client->sock, POLLER_WRITE | POLLER_READ);
                        socket_close(client->sock);

                        num_disconnects++;

                        if (num_disconnects == num_clients)
                        {
                            quit = true;
                            break;
                        }

                        break;
                    }
                    else if (errno == EAGAIN)
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
#if defined(_WIN32)
                    n = send(client->sock, (char*)&out[0], (int)out.size(), 0);
#else
                    n = send(client->sock, &out[0], out.size(), 0);
#endif

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
                            poller.remove(event.sock, POLLER_WRITE);
                            break;
                        }
                    }
                    else if (errno == EAGAIN)
                    {
                        break;
                    }
                    else
                    {
                        OE_TEST(false);
                    }
                }
            }
        }
    }

    socket_close(listener);

    socket_cleanup();
}
