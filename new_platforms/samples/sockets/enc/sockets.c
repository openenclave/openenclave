/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include "sockets_t.h"
#include "tcps_string_t.h"

/* This client connects to an echo server, sends a text message,
 * and outputs the text reply.
 */
int ecall_RunClient(char* server, char* serv)
{
    int status = OE_FAILURE;
    struct addrinfo* ai = NULL;
    SOCKET s = INVALID_SOCKET;

    printf("Connecting to %s %s...\n", server, serv);

    /* Resolve server name. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(server, serv, &hints, &ai);
    if (err != 0) {
        goto Done;
    }

    /* Create connection. */
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        goto Done;
    }
    if (connect(s, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        goto Done;
    }

    /* Send a message, prefixed by its size. */
    const char *message = "Hello, world!";
    printf("Sending message: %s\n", message);
    int messageLength = strlen(message);
    int netMessageLength = htonl(messageLength);
    int bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }
    bytesSent = send(s, message, messageLength, 0);
    if (bytesSent == SOCKET_ERROR) {
        goto Done;
    }

    /* Receive a text reply, prefixed by its size. */
    int replyLength;
    char reply[80];
    int bytesReceived = recv(s, (char*)&replyLength, sizeof(replyLength), MSG_WAITALL);
    if (bytesReceived == SOCKET_ERROR) {
        goto Done;
    }
    replyLength = ntohl(replyLength);
    if (replyLength > sizeof(reply) - 1) {
        goto Done;
    }
    bytesReceived = recv(s, reply, replyLength, MSG_WAITALL);
    if (bytesReceived != bytesSent) {
        goto Done;
    }

    /* Add null termination. */
    reply[replyLength] = 0;

    /* Print the reply. */
    printf("Received reply: %s\n", reply);

    status = OE_OK;

Done:
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return status;
}

/* This server acts as an echo server.  It accepts a connection,
 * receives messages, and echoes them back.
 */
int ecall_RunServer(char* serv)
{
    int status = OE_FAILURE;
    struct addrinfo* ai = NULL;
    SOCKET listener = INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;

    /* Resolve service name. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int err = getaddrinfo(NULL, serv, &hints, &ai);
    if (err != 0) {
        goto Done;
    }

    /* Create listener socket. */
    listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener == INVALID_SOCKET) {
        goto Done;
    }
    if (bind(listener, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        goto Done;
    }
    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        goto Done;
    }
    printf("Listening on %s...\n", serv);

    while (true)
    {
        /* Accept a client connection. */
        struct sockaddr_storage addr;
        int addrlen = sizeof(addr);
        s = accept(listener, (struct sockaddr*)&addr, &addrlen);
        if (s == INVALID_SOCKET) {
            continue;
        }

        while (true)
        {
            /* Receive a text message, prefixed by its size. */
            int netMessageLength;
            int messageLength;
            char message[80];
            int bytesReceived = recv(s, (char*)&netMessageLength, sizeof(netMessageLength), MSG_WAITALL);
            if (bytesReceived == SOCKET_ERROR) {
                goto Close;
            }
            messageLength = ntohl(netMessageLength);
            if (messageLength > sizeof(message)) {
                goto Close;
            }
            bytesReceived = recv(s, message, messageLength, MSG_WAITALL);
            if (bytesReceived != messageLength) {
                goto Close;
            }

            /* Send it back to the client, prefixed by its size. */
            int bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
            if (bytesSent == SOCKET_ERROR) {
                goto Close;
            }
            bytesSent = send(s, message, messageLength, 0);
            if (bytesSent == SOCKET_ERROR) {
                goto Close;
            }
        }
    Close:
        if (s != INVALID_SOCKET) {
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }

    status = OE_OK;

Done:
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
    }
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    return status;
}
