// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if !defined(_MSC_VER)

// Visual C is allergic to gnu pragmas
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#else
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wconversion"
#endif
#endif

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#if defined(_MSC_VER)
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/tests.h>
#include <windows.h>

typedef oe_socklen_t socklen_t;
typedef oe_in_port_t in_port_t;

static void sleep(int secs)
{
    Sleep(secs * 1000);
}

#else
#include <netinet/in.h>
#include <openenclave/internal/tests.h>

#include "socket_test_u.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "socket_test_u.h"

#define SERVER_PORT "12345"

#if defined(_WIN32)
DWORD enclave_server_thread(void* arg)
#else
void* enclave_server_thread(void* arg)
#endif
{
    oe_enclave_t* server_enclave = NULL;
    int retval = 0;
    oe_result_t result;
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_socket_test_enclave(
        arg, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &server_enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_run_server(server_enclave, &retval) == OE_OK);
    //    OE_TEST(oe_terminate_enclave(server_enclave) == OE_OK);
    sleep(3);
    return 0;
}

#if defined(_WIN32)
DWORD host_server_thread(void* arg)
#else
void* host_server_thread(void* arg)
#endif
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    int64_t listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int64_t connfd = 0;
    struct sockaddr_in serv_addr = {0};

    (void)arg;
    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);

    int rtn =
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void*)&optVal, optLen);
    if (rtn > 0)
    {
        printf("setsockopt failed errno = %d\n", errno);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1492);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    while (1)
    {
        printf("host: accepting\n");
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
        printf("accepted fd = %lld\n", connfd);
        if (connfd >= 0)
        {
#if defined(_WIN32)
            DWORD n = 0;
            int err = 0;
            n = send(connfd, TESTDATA, (DWORD)strlen(TESTDATA), 0);
            if (n < 0)
            {
                err = WSAGetLastError();
                printf("write err=%d, data bytes = %ld\n", err, n);
            }
#else
            ssize_t n = write(connfd, TESTDATA, strlen(TESTDATA));
#endif
            OE_TEST((size_t)n == strlen(TESTDATA));
            printf("write test data\n");
#if defined(_WIN32)
            CloseHandle((HANDLE)connfd);
#else
            close(connfd);
#endif
            break;
        }
        sleep(1);
    }

#if defined(_WIN32)
    CloseHandle((HANDLE)listenfd);
#else
    close(listenfd);
#endif
    printf("exit from server thread\n");
    return 0;
}

char* host_client(in_port_t port)

{
    int64_t sockfd = 0;
    ssize_t n = 0;
    static char recvBuff[1024];
    struct sockaddr_in serv_addr = {0};

    memset(recvBuff, '0', sizeof(recvBuff));
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return NULL;
    }

#if !defined(_WIN32)
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);

    int retries = 0;
    static const int max_retries = 400;
    printf("host client:socket fd = %lld\n", sockfd);
    printf("host client:Connecting...\n");
    while (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed errno = %d\n", errno);
#if defined(_WIN32)
            CloseHandle((HANDLE)sockfd);
#else
            close(sockfd);
#endif
            return NULL;
        }
        else
        {
            printf("Connect Failed. errno = %d Retrying \n", errno);
            sleep(1);
        }
    }

    do
    {
#if defined(_WIN32)
        DWORD n = 0;
        int err = 0;
        n = recv(sockfd, recvBuff, sizeof(recvBuff), 0);
#else
        n = read(sockfd, recvBuff, sizeof(recvBuff));
#endif
        if (n > 0)
        {
            recvBuff[n] = '\0';
            printf("host finished reading: %ld bytes...\n", n);
            break;
        }
        else
        {
            if (errno != EAGAIN)
            {
                printf("Read error, errno = %d\n", errno);
#if defined(_WIN32)
                CloseHandle((HANDLE)sockfd);
#else
                close(sockfd);
#endif
                return NULL;
            }
            else
            {
                sleep(1);
            }
        }
    } while (1);

#if defined(_WIN32)
    CloseHandle((HANDLE)sockfd);
#else
    close(sockfd);
#endif
    return &recvBuff[0];
}

int main(int argc, const char* argv[])
{
    static char TESTDATA[] = "This is TEST DATA\n";
    oe_result_t result;
    oe_enclave_t* client_enclave = NULL;
    int ret = 0;
    char test_data_rtn[1024] = {0};
    ssize_t test_data_len = 1024;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

#if defined(_WIN32)
    static WSADATA startup_data = {0};

    // Initialize Winsock
    (void)WSAStartup(MAKEWORD(2, 2), &startup_data);

#endif
#if 0
    // host server to host client
    OE_TEST(
        pthread_create(&server_thread_id, NULL, host_server_thread, NULL) == 0);

    sleep(3); // Give the server time to launch
    char* test_data = host_client();

    printf("received: %s\n", test_data);
    OE_TEST(strcmp(test_data, TESTDATA) == 0);

    pthread_join(server_thread_id, NULL);

    sleep(3); // Let the net stack settle
#endif

#if defined(_WIN32)
    HANDLE server_thread_h =
        CreateThread(NULL, 0, host_server_thread, NULL, 0, NULL);
    OE_TEST(server_thread_h != INVALID_HANDLE_VALUE);
#else
    pthread_t server_thread_id = 0;
    // host server to enclave client
    OE_TEST(
        pthread_create(&server_thread_id, NULL, host_server_thread, NULL) == 0);
#endif

    sleep(3); // Give the server time to launch
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_socket_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);

    OE_TEST(result == OE_OK);

    test_data_len = 1024;
    OE_TEST(
        ecall_run_client(client_enclave, &ret, test_data_rtn, &test_data_len) ==
        OE_OK);

    printf("host received: %.*s\n", (int)test_data_len, test_data_rtn);

#if defined(_WIN32)
    WaitForSingleObject(server_thread_h, INFINITE);
    server_thread_h = INVALID_HANDLE_VALUE;
#else
    pthread_join(server_thread_id, NULL);
#endif
    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);

    // enclave server to host client
    sleep(3); // Give the server time to launch

#if defined(_WIN32)
    server_thread_h =
        CreateThread(NULL, 0, enclave_server_thread, argv[1], 0, NULL);
    OE_TEST(server_thread_h != INVALID_HANDLE_VALUE);
#else
    OE_TEST(
        pthread_create(
            &server_thread_id, NULL, enclave_server_thread, (void*)argv[1]) ==
        0);
#endif

    sleep(3); // Give the server time to launch

    char* test_data = host_client(1493);

    printf("received from enclave server: %s\n", test_data);
    OE_TEST(strcmp(test_data, TESTDATA) == 0);

#if defined(_WIN32)
    WaitForSingleObject(server_thread_h, INFINITE);
    server_thread_h = INVALID_HANDLE_VALUE;
#else
    pthread_join(server_thread_id, NULL);
#endif

    printf("=== passed all tests (socket_test)\n");

    return 0;
}
