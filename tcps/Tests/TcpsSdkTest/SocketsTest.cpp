/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tcps_u.h>
#include <TcpsSdkTestTA_u.h>
#include "gtest/gtest.h"
#include "TrustedAppTest.h"

class SocketsTest : public TrustedAppTest {
public:
    Tcps_StatusCode RunTestClient(void)
    {
        Tcps_StatusCode uStatus = Tcps_BadCommunicationError;
        struct addrinfo* ai = NULL;
        SOCKET s = INVALID_SOCKET;

        /* Resolve server name. */
        struct addrinfo hints = { 0 };
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int err = getaddrinfo(this->server.buffer, this->port.buffer, &hints, &ai);
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

        uStatus = Tcps_Good;

    Done:
        if (s != INVALID_SOCKET) {
            closesocket(s);
        }
        if (ai != NULL) {
            freeaddrinfo(ai);
        }
        return uStatus;
    }

    Tcps_StatusCode StartTestServer(void)
    {
        Tcps_StatusCode uStatus = Tcps_BadCommunicationError;
        struct addrinfo* ai = NULL;
        SOCKET listener = INVALID_SOCKET;
        SOCKET s = INVALID_SOCKET;

        COPY_BUFFER_FROM_STRING(this->port, "12345");

        /* Resolve service name. */
        struct addrinfo hints = { 0 };
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        int err = getaddrinfo(NULL, this->port.buffer, &hints, &ai);
        if (err != 0) {
            return Tcps_BadCommunicationError;
        }

        /* Create listener socket. */
        listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listener == INVALID_SOCKET) {
            freeaddrinfo(ai);
            return Tcps_BadCommunicationError;
        }
        if (bind(listener, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
            closesocket(listener);
            freeaddrinfo(ai);
            return Tcps_BadCommunicationError;
        }

        if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listener);
            return Tcps_BadCommunicationError;
        }

        /* Signal client thread that we're ready to accept connections. */
        SetEvent(this->readyEvent);

        /* Accept a client connection. */
        struct sockaddr_storage addr;
        int addrlen = sizeof(addr);
        s = accept(listener, (struct sockaddr*)&addr, &addrlen);
        if (s == INVALID_SOCKET) {
            goto Done;
        }

        /* Receive a text message, prefixed by its size. */
        int netMessageLength;
        int messageLength;
        char message[80];
        int bytesReceived = recv(s, (char*)&netMessageLength, sizeof(netMessageLength), MSG_WAITALL);
        if (bytesReceived == SOCKET_ERROR) {
            goto Done;
        }
        messageLength = ntohl(netMessageLength);
        if (messageLength > sizeof(message)) {
            goto Done;
        }
        bytesReceived = recv(s, message, messageLength, MSG_WAITALL);
        if (bytesReceived != messageLength) {
            goto Done;
        }

        /* Send it back to the client, prefixed by its size. */
        int bytesSent = send(s, (char*)&netMessageLength, sizeof(netMessageLength), 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }
        bytesSent = send(s, message, messageLength, 0);
        if (bytesSent == SOCKET_ERROR) {
            goto Done;
        }
        uStatus = Tcps_Good;

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
        return uStatus;
    }

protected:
    sgx_enclave_id_t taid;
    buffer256 server;
    buffer256 port;
    HANDLE readyEvent;
};

DWORD WINAPI StartTestServer(_In_ LPVOID lpParameter)
{
    SocketsTest* self = (SocketsTest*)lpParameter;
    return self->StartTestServer();
}

DWORD WINAPI RunTestClient(_In_ LPVOID lpParameter)
{
    SocketsTest* self = (SocketsTest*)lpParameter;
    return self->RunTestClient();
}

TEST_F(SocketsTest, EchoClient_Success)
{
    Tcps_StatusCode uStatus;
    HANDLE hServerThread;

    COPY_BUFFER_FROM_STRING(this->server, "localhost");

    // Create a test server.
    this->readyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    ASSERT_TRUE(this->readyEvent != NULL);
    hServerThread = CreateThread(NULL, 0, ::StartTestServer, this, 0, NULL);
    ASSERT_TRUE(hServerThread != NULL);

    // Wait for server thread to be ready.
    WaitForSingleObject(this->readyEvent, INFINITE);
    CloseHandle(readyEvent);

    AcquireTAMutex();
    sgx_status_t sgxStatus = ecall_RunClient(GetTAId(), &uStatus, this->server, this->port);
    ReleaseTAMutex();
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    // Clean up test server.
    WaitForSingleObject(hServerThread, INFINITE);
    CloseHandle(hServerThread);
} 

TEST_F(SocketsTest, EchoServer_Success)
{
    Tcps_StatusCode uStatus;
    HANDLE hClientThread;

    COPY_BUFFER_FROM_STRING(this->server, "localhost");
    COPY_BUFFER_FROM_STRING(this->port, "12345");

    AcquireTAMutex();
    sgx_status_t sgxStatus = ecall_StartServer(GetTAId(), &uStatus, this->port);
    ReleaseTAMutex();
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    // Run a test client.
    hClientThread = CreateThread(NULL, 0, ::RunTestClient, this, 0, NULL);
    ASSERT_TRUE(hClientThread != NULL);

    // Clean up test server.
    AcquireTAMutex();
    sgxStatus = ecall_FinishServer(GetTAId(), &uStatus);
    ReleaseTAMutex();
    ASSERT_EQ(SGX_SUCCESS, sgxStatus);
    ASSERT_EQ(Tcps_Good, uStatus);

    // Clean up test client.
    WaitForSingleObject(hClientThread, INFINITE);
    CloseHandle(hClientThread);
}
