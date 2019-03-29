// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
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

#include "socket_test_u.h"

#define SERVER_PORT "12345"

void* enclave_server_thread(void* arg)
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
    return NULL;
}

void* host_server_thread(void* arg)
{
    const static char TESTDATA[] = "This is TEST DATA\n";
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int connfd = 0;
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
        printf("accepted fd = %d\n", connfd);
        if (connfd >= 0)
        {
            write(connfd, TESTDATA, strlen(TESTDATA));
            printf("write test data\n");
            close(connfd);
            break;
        }
        sleep(1);
    }

    close(listenfd);
    printf("exit from server thread\n");
    return NULL;
}

char* host_client(in_port_t port)

{
    int sockfd = 0;
    ssize_t n = 0;
    static char recvBuff[1024];
    struct sockaddr_in serv_addr = {0};

    memset(recvBuff, '0', sizeof(recvBuff));
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return NULL;
    }

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);

    int retries = 0;
    static const int max_retries = 400;
    printf("host client:socket fd = %d\n", sockfd);
    printf("host client:Connecting...\n");
    while (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed errno = %d\n", errno);
            close(sockfd);
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
        n = read(sockfd, recvBuff, sizeof(recvBuff));
        if (n > 0)
        {
            recvBuff[n] = '\0';
            printf("finished reading: %ld bytes...\n", n);
            break;
        }
        else
        {
            if (errno != EAGAIN)
            {
                printf("Read error, errno = %d\n", errno);
                close(sockfd);
                return NULL;
            }
            else
            {
                sleep(1);
            }
        }
    } while (1);

    close(sockfd);
    return &recvBuff[0];
}

int main(int argc, const char* argv[])
{
    static char TESTDATA[] = "This is TEST DATA\n";
    oe_result_t result;
    oe_enclave_t* client_enclave = NULL;
    pthread_t server_thread_id = 0;
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

    // host server to enclave client
    OE_TEST(
        pthread_create(&server_thread_id, NULL, host_server_thread, NULL) == 0);

    sleep(3); // Give the server time to launch
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_socket_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);

    OE_TEST(result == OE_OK);

    test_data_len = 1024;
    OE_TEST(
        ecall_run_client(client_enclave, &ret, test_data_rtn, &test_data_len) ==
        OE_OK);

    printf("host received: %s\n", test_data_rtn);

    pthread_join(server_thread_id, NULL);
    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);

    // enclave server to host client
    sleep(3); // Give the server time to launch
    OE_TEST(
        pthread_create(
            &server_thread_id, NULL, enclave_server_thread, (void*)argv[1]) ==
        0);

    sleep(3); // Give the server time to launch

    char* test_data = host_client(1493);

    printf("received from enclave server: %s\n", test_data);
    OE_TEST(strcmp(test_data, TESTDATA) == 0);

    pthread_join(server_thread_id, NULL);

    printf("=== passed all tests (socket_test)\n");

    return 0;
}
