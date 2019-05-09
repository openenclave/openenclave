// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#if defined(_MSC_VER)
#define OE_NEED_STD_NAMES
// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format on
static void sleep(int secs)
{
    Sleep(secs * 1000);
}
typedef HANDLE pthread_t;
typedef DWORD socklen_t;
typedef SOCKET socket_t;
#else
typedef int socket_t;
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#endif
#include <stdio.h>

#include "epoll_test_u.h"

#define SERVER_PORT "12345"

void oe_epoll_install_hostepoll(void);

#if defined(__linux__)
void sigpipe_handler(int unused)
{
    (void)unused;
    // Doens't do anything. We expect sigpipe from the server pipe
    printf("received sigpipe\n");
}
#endif

void* host_server_thread(void* arg)
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    socket_t listenfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {0};
    static size_t MAX_ACCEPTS = 3;

    OE_UNUSED(arg);

    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    int r = -1;

#if defined(__linux__)
    struct sigaction action = {{sigpipe_handler}};
    sigaction(SIGPIPE, &action, NULL);
#endif

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1642);

    while (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("bind failed errno = %d\n", errno);
        sleep(5);
    }

    listen(listenfd, 10);

    r = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void*)&optVal, optLen);
    OE_TEST(r == 0);

    for (size_t i = 0; i < MAX_ACCEPTS; i++)
    {
        socket_t connfd;
        ssize_t n;

        printf("host server: accepting\n");
        OE_TEST((connfd = accept(listenfd, NULL, NULL)) >= 0);

#if defined(__linux__)
        n = write(connfd, TESTDATA, strlen(TESTDATA));
#else
        n = send(connfd, TESTDATA, (int)strlen(TESTDATA), 0);
#endif
        OE_TEST(n == (int)strlen(TESTDATA));
        sleep(1);

#if defined(__linux__)
        close(connfd);
#else
        closesocket(connfd);
#endif
    };

#if defined(__linux__)
    close(listenfd);
#else
    closesocket(listenfd);
#endif
    printf("exit from server thread\n");
    return NULL;
}

static void* _run_wake_test(void* arg)
{
    oe_enclave_t* enclave = (oe_enclave_t*)arg;
    int ret;

    OE_TEST(ecall_wait_test(enclave, &ret) == 0);
    OE_TEST(ret == 0);

    return NULL;
}

int main(int argc, const char* argv[])
{
    static char TESTDATA[] = "This is TEST DATA\n";
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    pthread_t server_thread_id = 0;
    int ret = 0;
    char test_data_r[1024] = {0};
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

#if !defined(__linux__)
    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif

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
#if !defined(__linux__)
    server_thread_id = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)host_server_thread,
        (void*)&done,
        0,
        NULL);
    OE_TEST(server_thread_id != INVALID_HANDLE_VALUE);
#else
    OE_TEST(
        pthread_create(
            &server_thread_id, NULL, host_server_thread, (void*)&done) == 0);
#endif

    sleep(3); // Give the server time to launch
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_epoll_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_device_init(enclave, &ret, tmp_dir) == OE_OK);

    /* poll test */
    {
        test_data_len = 1024;
        OE_TEST(
            ecall_poll_test(
                enclave, &ret, test_data_len, test_data_r, use_libc) == OE_OK);

        sleep(5);

        printf("poll: host received: %s\n", test_data_r);
        OE_TEST(strncmp(TESTDATA, test_data_r, strlen(TESTDATA)) == 0);
    }

    /* epoll test */
    {
        test_data_len = 1024;
        OE_TEST(
            ecall_epoll_test(
                enclave, &ret, test_data_len, test_data_r, use_libc) == OE_OK);

        sleep(5);

        printf("epoll: host received: %s\n", test_data_r);
        OE_TEST(
            strncmp("socket success", test_data_r, strlen("socket success")) ==
            0);
    }

    /* select test. */
    {
        test_data_len = 1024;
        OE_TEST(
            ecall_select_test(
                enclave, &ret, test_data_len, test_data_r, use_libc) == OE_OK);

        printf("select: host received: %s\n", test_data_r);
        OE_TEST(strncmp(TESTDATA, test_data_r, strlen(TESTDATA)) == 0);

        OE_TEST(ecall_device_shutdown(enclave) == OE_OK);
    }

    done = 2;
#if defined(_WIN32)
    ret = WaitForSingleObject(server_thread_id, INFINITE);
#else
    pthread_join(server_thread_id, NULL);
#endif

    /* Test the wake feature. */
    {
        pthread_t thread;

#if defined(_WIN32)
        thread = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)_run_wake_test,
            (void*)enclave,
            0,
            NULL);
        OE_TEST(server_thread_id != INVALID_HANDLE_VALUE);
#else
        OE_TEST(pthread_create(&thread, NULL, _run_wake_test, enclave) == 0);
#endif

        sleep(3);

#if defined(__linux__)
        for (size_t i = 0; i < 3; i++)
        {
            OE_TEST(ecall_wake_test(enclave, &ret) == OE_OK);
        }
#endif

#if defined(_WIN32)
        ret = WaitForSingleObject(thread, INFINITE);
#else
        pthread_join(thread, NULL);
#endif
    }

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (epoll_test)\n");

    return 0;
}
