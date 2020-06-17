// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void init_ecall(void)
{
    OE_TEST(oe_load_module_host_socket_interface() == 0);
}

#define PORT 12345

static const char MSG[] = "abcdefghijklmnopqrstuvwxyz";
static const size_t NUM_MESSAGES = 1000;

void run_server_ecall(void)
{
    int sockfd;
    struct sockaddr_in server;
    char buf[1024];
    ssize_t n;
    size_t i;

    OE_TEST((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);

    /* Initialize the peer address. */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    /* Bind the socket to the peer address. */
    OE_TEST(bind(sockfd, (struct sockaddr*)&server, sizeof(server)) == 0);

    /* Process request from clients. */
    for (i = 0; i < NUM_MESSAGES; i++)
    {
        struct sockaddr_in addr;
        struct sockaddr* sa = (struct sockaddr*)&addr;
        socklen_t salen = sizeof(addr);

        memset(&addr, 0, sizeof(addr));

        /* Receive data from the server. */
        n = recvfrom(sockfd, buf, sizeof(buf), MSG_WAITALL, sa, &salen);
        printf("server: read %zd bytes\n", n);

        OE_TEST(n == sizeof(MSG));
        OE_TEST(memcmp(buf, MSG, (size_t)n) == 0);

        /* Send data to the server. */
        n = sendto(sockfd, buf, (size_t)n, MSG_CONFIRM, sa, salen);
        printf("server: wrote %zd bytes\n", n);
        OE_TEST(n == sizeof(MSG));
    }

    OE_TEST(close(sockfd) == 0);
}

void run_client_ecall(void)
{
    int sockfd;
    struct sockaddr_in addr;
    struct sockaddr* sa = (struct sockaddr*)&addr;
    socklen_t salen = sizeof(struct sockaddr);
    char buf[sizeof(MSG)];
    ssize_t n;

    OE_TEST((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);

    /* Initialize the peer address. */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    for (size_t i = 0; i < NUM_MESSAGES; i++)
    {
        /* Send data to the server. */
        n = sendto(sockfd, MSG, sizeof(MSG), MSG_CONFIRM, sa, salen);
        OE_TEST(n == sizeof(MSG));

        /* Receive data from the server. */
        n = recvfrom(sockfd, buf, (size_t)n, MSG_WAITALL, sa, &salen);
        OE_TEST(n == sizeof(MSG));
        OE_TEST(memcmp(buf, MSG, (size_t)n) == 0);
    }

    OE_TEST(close(sockfd) == 0);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
