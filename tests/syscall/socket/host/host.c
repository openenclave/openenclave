// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// ATTN: #define OE_LIBC_SUPPRESS_DEPRECATIONS

#if defined(_MSC_VER)
#include "../../platform/windows.h"
#else
#include "../../platform/linux.h"
#endif

#include <inttypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/types.h>
#include "socket_test_u.h"

#define SERVER_PORT "12345"

#if _WIN32
#define errno WSAGetLastError()
#endif

void* enclave_server_thread(void* arg)
{
    oe_enclave_t* enclave = NULL;
    int retval = 0;
    oe_result_t r;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_AUTO;

    r = oe_create_socket_test_enclave(arg, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    OE_TEST(ecall_run_server(enclave, &retval) == OE_OK);

    return NULL;
}

void* host_server_thread(void* arg)
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    socket_t listenfd = socket(AF_INET, SOCK_STREAM, 0);
    socket_t connfd = 0;
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

        printf("accepted fd=%lld\n", OE_LLD((int64_t)connfd));

        if (connfd >= 0)
        {
            printf("host: send test data\n");
            ssize_t n = sock_send(connfd, TESTDATA, strlen(TESTDATA), 0);
            OE_TEST((size_t)n == strlen(TESTDATA));
            sock_close(connfd);
            break;
        }
    }

    sock_close(listenfd);

    printf("exit from server thread\n");
    return NULL;
}

char* host_client(in_port_t port)
{
    socket_t sockfd = 0;
    ssize_t n = 0;
    static char recvBuff[1024];
    struct sockaddr_in serv_addr = {0};

    memset(recvBuff, '\0', sizeof(recvBuff));
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return NULL;
    }

    sock_set_blocking(sockfd, false);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(port);

    int retries = 0;
    static const int max_retries = 400;
    printf("host client:socket fd = %lld\n", OE_LLD((int64_t)sockfd));
    printf("host client:Connecting...\n");

    while (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n Error : Connect Failed errno = %d\n", errno);
            sock_close(sockfd);
            return NULL;
        }
#if _WIN32
        else if (errno == WSAEISCONN)
        {
            break;
        }
#endif
        {
            printf("Connect Failed. errno = %d Retrying \n", errno);
            sleep_msec(100);
        }
    }

    do
    {
        if ((n = sock_recv(sockfd, recvBuff, sizeof(recvBuff), 0)) > 0)
        {
            recvBuff[n] = '\0';
            printf("host finished reading: %" PRIu64 " bytes...\n", n);
            break;
        }
        else
        {
            if (errno != EAGAIN)
            {
                printf("Read error, errno = %d\n", errno);
                sock_close(sockfd);
                return NULL;
            }
            else
            {
                sleep_msec(100);
            }
        }
    } while (1);

    sock_close(sockfd);

    return &recvBuff[0];
}

static void _run_host_server_test(const char* path)
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    int ret = 0;
    char test_data_rtn[1024] = {0};
    ssize_t test_data_len = 1024;
    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_AUTO;
    thread_t thread;

    sock_startup();

    OE_TEST(thread_create(&thread, host_server_thread, NULL) == 0);

    // Give the server time to launch
    sleep_msec(250);

    r = oe_create_socket_test_enclave(path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    test_data_len = 1024;
    OE_TEST(
        ecall_run_client(enclave, &ret, test_data_rtn, &test_data_len) ==
        OE_OK);

    printf("host received: %.*s\n", (int)test_data_len, test_data_rtn);

    thread_join(thread);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed %s\n", __FUNCTION__);
}

static void _run_enclave_server_test(const char* path)
{
    static char TESTDATA[] = "This is TEST DATA\n";
    thread_t thread;
    const in_port_t PORT = 1493;

    // enclave server to host client
    OE_TEST(thread_create(&thread, enclave_server_thread, (void*)path) == 0);

    // Give the server time to launch
    sleep_msec(250);

    char* test_data = host_client(PORT);

    printf("received from enclave server: %s\n", test_data);
    OE_TEST(strcmp(test_data, TESTDATA) == 0);

    thread_join(thread);

    sock_cleanup();

    printf("=== passed %s\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    sock_startup();

    _run_host_server_test(argv[1]);
    _run_enclave_server_test(argv[1]);

    sock_cleanup();

    printf("=== passed all tests (socket_test)\n");

    return 0;
}
