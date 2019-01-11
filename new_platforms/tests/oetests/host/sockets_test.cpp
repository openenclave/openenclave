/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX

#include "sal_unsup.h"
#include "stdext.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>

#define SOCKET          int
#define INVALID_SOCKET  -1
#define SOCKET_ERROR    -1
#define closesocket(x)  close(x)
#define WINAPI
#define LPVOID          void *
#define SetEvent(x)     sem_post(&(x))

#else  // !LINUX

#include <winsock2.h>
#include <ws2tcpip.h>

#define socklen_t       int

#endif  // LINUX

#include <openenclave/host.h>
#include "oetests_u.h"
#include "gtest/gtest.h"
#include "TrustedAppTest.h"

class SocketsTest : public TrustedAppTest {
public:
    oe_result_t RunTestClient(void)
    {
        oe_result_t uStatus = OE_FAILURE;
        struct addrinfo* ai = NULL;
        SOCKET s = INVALID_SOCKET;
        struct addrinfo hints = { 0 };
        int err;
        const char *message = "Hello, world!";
        int messageLength;
        int netMessageLength;
        int bytesSent;
        int replyLength;
        char reply[80];
        int bytesReceived; 

        /* Resolve server name. */
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        err = getaddrinfo(this->server, this->port, &hints, &ai);
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
        messageLength = strlen(message);
        netMessageLength = htonl(messageLength);
        bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }
        bytesSent = send(s, message, messageLength, 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }

        /* Receive a text reply, prefixed by its size. */
        bytesReceived = recv(s, (char*)&replyLength, sizeof(replyLength), MSG_WAITALL);
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

        uStatus = OE_OK;

    Done:
        if (s != INVALID_SOCKET) {
            closesocket(s);
        }
        if (ai != NULL) {
            freeaddrinfo(ai);
        }
        return uStatus;
    }

    oe_result_t StartTestServer(void)
    {
        oe_result_t uStatus = OE_FAILURE;
        struct addrinfo* ai = NULL;
        SOCKET listener = INVALID_SOCKET;
        SOCKET s = INVALID_SOCKET;
        struct addrinfo hints = { 0 };
        int err;
        struct sockaddr_storage addr;
        socklen_t addrlen;
        int netMessageLength;
        int messageLength;
        char* message = NULL;
        int bytesReceived;
        int bytesSent;

        strcpy_s(this->port, sizeof(this->port), "12345");

        /* Resolve service name. */
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        err = getaddrinfo(NULL, this->port, &hints, &ai);
        if (err != 0) {
            return OE_FAILURE;
        }

        /* Create listener socket. */
        listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listener == INVALID_SOCKET) {
            freeaddrinfo(ai);
            return OE_FAILURE;
        }
        if (bind(listener, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
            closesocket(listener);
            freeaddrinfo(ai);
            return OE_FAILURE;
        }

        if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listener);
            return OE_FAILURE;
        }

        /* Signal client thread that we're ready to accept connections. */
        SetEvent(this->readyEvent);

        /* Accept a client connection. */
        addrlen = sizeof(addr);
        s = accept(listener, (struct sockaddr*)&addr, &addrlen);
        if (s == INVALID_SOCKET) {
            goto Done;
        }

        /* Receive message size. */
        bytesReceived = recv(s, (char*)&netMessageLength, sizeof(netMessageLength), MSG_WAITALL);
        if (bytesReceived == SOCKET_ERROR) {
            goto Done;
        }
        messageLength = ntohl(netMessageLength);
        if (messageLength > 65536) {
            goto Done;
        }
        message = (char*)malloc(messageLength);
        if (message == NULL) {
            goto Done;
        }

        /* Receive the message. */
        bytesReceived = recv(s, message, messageLength, MSG_WAITALL);
        if (bytesReceived != messageLength) {
            goto Done;
        }

        /* Send it back to the client, prefixed by its size. */
        bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }
        bytesSent = send(s, message, messageLength, 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }
        uStatus = OE_OK;

    Done:
        free(message);
        if (s != INVALID_SOCKET) {
            closesocket(s);
        }
        if (listener != INVALID_SOCKET) {
            closesocket(listener);
        }
        if (ai != NULL) {
            freeaddrinfo(ai);
        }
        return uStatus;
    }

protected:
    char server[256];
    char port[256];
#ifdef LINUX
    sem_t readyEvent;
#else
    HANDLE readyEvent;
#endif
};

#ifdef LINUX
void *
#else
DWORD
#endif
WINAPI StartTestServer(_In_ LPVOID lpParameter)
{
    SocketsTest* self = (SocketsTest*)lpParameter;
    return
#ifdef LINUX
    (void *)
#else
    (DWORD)
#endif
    self->StartTestServer();
}

#ifdef LINUX
void *
#else
DWORD
#endif
WINAPI RunTestClient(_In_ LPVOID lpParameter)
{
    SocketsTest* self = (SocketsTest*)lpParameter;
    return
#ifdef LINUX
    (void *)
#else
    (DWORD)
#endif
    self->RunTestClient();
}

TEST_F(SocketsTest, EchoClient_Success)
{
    oe_result_t uStatus;
#ifdef LINUX
    pthread_t hServerThread;
#else
    HANDLE hServerThread;
#endif

    strcpy_s(this->server, sizeof(this->server), "localhost");

#ifdef LINUX
    // Create a test server.
    ASSERT_EQ(sem_init(&this->readyEvent, 0, 0), 0);
    ASSERT_EQ(pthread_create(&hServerThread, NULL, ::StartTestServer, this), 0);
    
    // Wait for server thread to be ready.
    sem_wait(&this->readyEvent);
    sem_destroy(&this->readyEvent);
#else
    // Create a test server.
    this->readyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    ASSERT_TRUE(this->readyEvent != NULL);
    
    hServerThread = CreateThread(NULL, 0, ::StartTestServer, this, 0, NULL);
    ASSERT_TRUE(hServerThread != NULL);
    
    // Wait for server thread to be ready.
    WaitForSingleObject(this->readyEvent, INFINITE);
    CloseHandle(readyEvent);
#endif

    oe_result_t oeResult = ecall_RunClient(GetOEEnclave(), &uStatus, this->server, this->port);
    ASSERT_EQ(OE_OK, oeResult);
    ASSERT_EQ(OE_OK, uStatus);

    // Clean up test server.
#ifdef LINUX
    pthread_join(hServerThread, NULL);
#else
    WaitForSingleObject(hServerThread, INFINITE);
    CloseHandle(hServerThread);
#endif
} 

TEST_F(SocketsTest, EchoServer_Success)
{
    oe_result_t uStatus;
#ifdef LINUX
    pthread_t hClientThread;
#else
    HANDLE hClientThread;
#endif

    strcpy_s(this->server, sizeof(this->server), "localhost");
    strcpy_s(this->port, sizeof(this->port), "12346");

    oe_result_t oeResult = ecall_StartServer(GetOEEnclave(), &uStatus, this->port);
    ASSERT_EQ(OE_OK, oeResult);
    ASSERT_EQ(OE_OK, uStatus);

    // Run a test client.
#ifdef LINUX
    ASSERT_EQ(pthread_create(&hClientThread, NULL, ::RunTestClient, this), 0);
#else
    hClientThread = CreateThread(NULL, 0, ::RunTestClient, this, 0, NULL);
    ASSERT_TRUE(hClientThread != NULL);
#endif

    // Clean up test server.
    oeResult = ecall_FinishServer(GetOEEnclave(), &uStatus);
    ASSERT_EQ(OE_OK, oeResult);
    ASSERT_EQ(OE_OK, uStatus);

    // Clean up test client.
#ifdef LINUX
    pthread_join(hClientThread, NULL);
#else
    WaitForSingleObject(hClientThread, INFINITE);
    CloseHandle(hClientThread);
#endif
}
