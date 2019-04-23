// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#include <netinet/in.h>
#include <openenclave/internal/tests.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "epoll_test_u.h"

#define SERVER_PORT "12345"

void oe_epoll_install_hostepoll(void);

void sigpipe_handler(int unused)
{
    (void)unused;
    // Doens't do anything. We expect sigpipe from the server pipe
    printf("received sigpipe\n");
}

void* host_server_thread(void* arg)
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int connfd = 0;
    struct sockaddr_in serv_addr = {0};

    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    int* done = (int*)arg;
    int rtn = -1;

    struct sigaction action = {{sigpipe_handler}};
    sigaction(SIGPIPE, &action, NULL);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1642);

    while (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("bind failed errno = %d\n", errno);
        sleep(5);
    }

    listen(listenfd, 10);

    rtn =
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void*)&optVal, optLen);
    if (rtn < 0)
    {
        printf("setsockopt failed errno = %d\n", errno);
    }

    do
    {
        int n = 0;
        connfd = -1;
        do
        {
            printf("accepting\n");
            connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
            printf("accepted fd = %d\n", connfd);
        } while (connfd < 0);

        while (!*done)
        {
            ssize_t numbytes = write(connfd, TESTDATA, strlen(TESTDATA));
            printf("write test data\n");
            if (n++ > 3 || numbytes < 0)
                break;
            sleep(1);
        }
        close(connfd);
    } while (*done != 2);

    close(listenfd);
    printf("exit from server thread\n");
    return NULL;
}

int main(int argc, const char* argv[])
{
    static char TESTDATA[] = "This is TEST DATA\n";
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    pthread_t server_thread_id = 0;
    int ret = 0;
    char test_data_rtn[1024] = {0};
    size_t test_data_len = 1024;
    int done = 0;
    bool use_libc = false;
    const char* tmp_dir;

    if (argc != 4)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH TMP_DIR [libc|corelibc]\n",
            argv[0]);
        return 1;
    }

    tmp_dir = argv[2];

    if (strcmp(argv[3], "libc") == 0)
        use_libc = true;
    else if (strcmp(argv[3], "corelibc") == 0)
        use_libc = false;
    else
    {
        fprintf(stderr, "%s: bad arg: %s\n", argv[0], argv[2]);
        return 1;
    }

    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    // host server to enclave client
    OE_TEST(
        pthread_create(
            &server_thread_id, NULL, host_server_thread, (void*)&done) == 0);

    sleep(3); // Give the server time to launch
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_epoll_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_device_init(enclave, &ret, tmp_dir) == OE_OK);

    test_data_len = 1024;
    OE_TEST(
        ecall_poll_test(
            enclave, &ret, test_data_len, test_data_rtn, use_libc) == OE_OK);

    sleep(5);

    printf("poll: host received: %s\n", test_data_rtn);
    OE_TEST(strncmp(TESTDATA, test_data_rtn, strlen(TESTDATA)) == 0);

    test_data_len = 1024;
    OE_TEST(
        ecall_epoll_test(
            enclave, &ret, test_data_len, test_data_rtn, use_libc) == OE_OK);

    sleep(5);

    printf("epoll: host received: %s\n", test_data_rtn);
    OE_TEST(
        strncmp("socket success", test_data_rtn, strlen("socket success")) ==
        0);

    test_data_len = 1024;
    OE_TEST(
        ecall_select_test(
            enclave, &ret, test_data_len, test_data_rtn, use_libc) == OE_OK);

    printf("select: host received: %s\n", test_data_rtn);
    OE_TEST(strncmp(TESTDATA, test_data_rtn, strlen(TESTDATA)) == 0);

    OE_TEST(ecall_device_shutdown(enclave) == OE_OK);

    done = 2;
    pthread_join(server_thread_id, NULL);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (epoll_test)\n");

    return 0;
}
