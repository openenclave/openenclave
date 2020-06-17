// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "client.h"
#if defined(_MSC_VER)
#pragma warning(disable : 4005)
// clang-format off
#include <winsock2.h>
#include <windows.h>
// clang-format off
typedef int socklen_t;
typedef SOCKET socket_t;

static void sleep(int n)
{
    Sleep(n * 1000);
}
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#endif
#include <openenclave/internal/tests.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void oe_abort(void);

#if defined(_MSC_VER)
void run_client(uint16_t port)
{
    socket_t sd;

    static WSADATA wsadata = {0};
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    /* Create the client socket. */
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        DWORD err = WSAGetLastError();
        printf("socket error = %d\n", err);
        OE_TEST("socket() failed" == NULL);
    }

    /* Connect to the server. */
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            DWORD err = WSAGetLastError();
            printf("connect error = %d\n", err);
            OE_TEST("connect() failed" == NULL);
        }
    }

    /* Send/receive a messsage to/from the server. */
    {
        static const uint8_t iov0[] = {'t', 'h', 'i', 's', ' '};
        static const uint8_t iov1[] = {'i', 's', ' '};
        static const uint8_t iov2[] = {'a', ' '};
        static const uint8_t iov3[] = {'t', 'e', 's', 't', '\0'};

        static const WSABUF iov[] = {
            {
                .buf = (void*)iov0,
                .len = sizeof(iov0),
            },
            {
                .buf = (void*)iov1,
                .len = sizeof(iov1),
            },
            {
                .buf = (void*)iov2,
                .len = sizeof(iov2),
            },
            {
                .buf = (void*)iov3,
                .len = sizeof(iov3),
            },
        };
        static const DWORD iovlen = sizeof(iov) / sizeof(iov[0]);
        ssize_t total_iov_size = 0;
        uint8_t iov0_buf[256];
        uint8_t iov1_buf[256];
        uint8_t iov2_buf[256];
        uint8_t iov3_buf[256];

        WSABUF iov_buf[4];
        WSAMSG msg_recv;
        WSAMSG msg_send;

        memset(&msg_send, 0, sizeof(msg_send));
        memset(&msg_recv, 0, sizeof(msg_recv));

        /* Get the total size of the iov[] array. */
        for (size_t i = 0; i < iovlen; i++)
            total_iov_size += (ssize_t)iov[i].len;

        /* Send a message. */
        {
            DWORD bytes_sent = 0;
            msg_send.lpBuffers = (WSABUF*)iov;
            msg_send.dwBufferCount = 4; // iovlen;

            if (WSASend(
                    sd,
                    msg_send.lpBuffers,
                    msg_send.dwBufferCount,
                    &bytes_sent,
                    0,
                    NULL,
                    NULL) != 0)
            {
                DWORD err = WSAGetLastError();
                printf("sendmsg failed err = %d\n", err);
                OE_TEST("sendmsg() failed" == NULL);
            }
            if (bytes_sent != total_iov_size)
                OE_TEST("sendmsg() failed to send all data" == NULL);
        }

        /* Receive the message. */
        {
            iov_buf[0].buf = iov0_buf;
            iov_buf[0].len = sizeof(iov0);
            iov_buf[1].buf = iov1_buf;
            iov_buf[1].len = sizeof(iov1);
            iov_buf[2].buf = iov2_buf;
            iov_buf[2].len = sizeof(iov2);
            iov_buf[3].buf = iov3_buf;
            iov_buf[3].len = sizeof(iov3);

            memset(&msg_recv, 0, sizeof(msg_recv));
            DWORD bytes_recvd = 0;
            msg_recv.lpBuffers = (WSABUF*)iov_buf;
            msg_recv.dwBufferCount = iovlen;

            if (WSARecv(
                    sd,
                    msg_recv.lpBuffers,
                    msg_recv.dwBufferCount,
                    &bytes_recvd,
                    &msg_recv.dwFlags,
                    NULL,
                    NULL) != 0)
            {
                DWORD err = WSAGetLastError();
                printf("recvmsg failed err = %d\n", err);
                OE_TEST("recvmsg() failed" == NULL);
            }
            if (bytes_recvd != total_iov_size)
                OE_TEST("recvmsg() failed to receive all data" == NULL);
        }

        /* Compare the message sent with the message received. */
        {
            OE_TEST(msg_send.dwBufferCount == msg_send.dwBufferCount);

            for (DWORD i = 0; i < msg_send.dwBufferCount; i++)
            {
                const WSABUF* p = &msg_send.lpBuffers[i];
                const WSABUF* q = &msg_send.lpBuffers[i];

                OE_TEST(p->len == q->len);
                OE_TEST(p->buf != NULL);
                OE_TEST(q->buf != NULL);
                OE_TEST(memcmp(p->buf, q->buf, p->len) == 0);
            }
        }
    }

    /* Send "quit" message the server. */
    {
        static const uint8_t iov0[] = {'q', 'u', 'i', 't', '\0'};

        static const WSABUF iov[] = {
            {
                .buf = (void*)iov0,
                .len = sizeof(iov0),
            },
        };
        static const DWORD iovlen = sizeof(iov) / sizeof(iov[0]);
        WSAMSG msg;
        memset(&msg, 0, sizeof(msg));

        msg.lpBuffers = (WSABUF*)iov;
        msg.dwBufferCount = iovlen;

        DWORD m = 0;
        if (WSASend(sd, msg.lpBuffers, msg.dwBufferCount, &m, 0, NULL, NULL) !=
            0)
        {
            OE_TEST("sendmsg() failed" == NULL);
        }

        if (m != sizeof(iov0))
            OE_TEST("sendmsg() failed: quit" == NULL);
    }

    if (!CloseHandle((HANDLE)sd))
    {
        OE_TEST("closeHandle() failed" == NULL);
    }
}
#else
void run_client(uint16_t port)
{
    int sd;

    /* Create the client socket. */
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        OE_TEST("socket() failed" == NULL);
    }

    /* Connect to the server. */
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            OE_TEST("connect() failed" == NULL);
        }
    }

    /* Send/receive a messsage to/from the server. */
    {
        static const uint8_t iov0[] = {'t', 'h', 'i', 's', ' '};
        static const uint8_t iov1[] = {'i', 's', ' '};
        static const uint8_t iov2[] = {'a', ' '};
        static const uint8_t iov3[] = {'t', 'e', 's', 't', '\0'};

        static const struct iovec iov[] = {
            {
                .iov_base = (void*)iov0,
                .iov_len = sizeof(iov0),
            },
            {
                .iov_base = (void*)iov1,
                .iov_len = sizeof(iov1),
            },
            {
                .iov_base = (void*)iov2,
                .iov_len = sizeof(iov2),
            },
            {
                .iov_base = (void*)iov3,
                .iov_len = sizeof(iov3),
            },
        };
        static const size_t iovlen = sizeof(iov) / sizeof(iov[0]);
        ssize_t total_iov_size = 0;
        uint8_t iov0_buf[256];
        uint8_t iov1_buf[256];
        uint8_t iov2_buf[256];
        uint8_t iov3_buf[256];
        struct iovec iov_buf[4];
        struct msghdr msg_recv;
        struct msghdr msg_send;

        memset(&msg_send, 0, sizeof(msg_send));
        memset(&msg_recv, 0, sizeof(msg_recv));

        /* Get the total size of the iov[] array. */
        for (size_t i = 0; i < iovlen; i++)
            total_iov_size += (ssize_t)iov[i].iov_len;

        /* Send a message. */
        {
            msg_send.msg_iov = (struct iovec*)iov;
            msg_send.msg_iovlen = 4; //(typeof(msg_send.msg_iovlen))iovlen;

            if (sendmsg(sd, &msg_send, 0) != total_iov_size)
                OE_TEST("sendmsg() failed" == NULL);
        }

        /* Receive the message. */
        {
            iov_buf[0].iov_base = iov0_buf;
            iov_buf[0].iov_len = sizeof(iov0);
            iov_buf[1].iov_base = iov1_buf;
            iov_buf[1].iov_len = sizeof(iov1);
            iov_buf[2].iov_base = iov2_buf;
            iov_buf[2].iov_len = sizeof(iov2);
            iov_buf[3].iov_base = iov3_buf;
            iov_buf[3].iov_len = sizeof(iov3);

            memset(&msg_recv, 0, sizeof(msg_recv));
            msg_recv.msg_iov = iov_buf;
            msg_recv.msg_iovlen = (typeof(msg_recv.msg_iovlen))iovlen;

            if (recvmsg(sd, &msg_recv, 0) != total_iov_size)
                OE_TEST("recvmsg() failed" == NULL);
        }

        /* Compare the message sent with the message received. */
        {
            OE_TEST(msg_send.msg_iovlen == msg_send.msg_iovlen);
            typedef typeof(msg_send.msg_iovlen) msg_iovlen_type;

            for (msg_iovlen_type i = 0; i < msg_send.msg_iovlen; i++)
            {
                const struct iovec* p = &msg_send.msg_iov[i];
                const struct iovec* q = &msg_send.msg_iov[i];

                OE_TEST(p->iov_len == q->iov_len);
                OE_TEST(p->iov_base != NULL);
                OE_TEST(q->iov_base != NULL);
                OE_TEST(memcmp(p->iov_base, q->iov_base, p->iov_len) == 0);
            }
        }
    }

    /* Send "quit" message the server. */
    {
        static const uint8_t iov0[] = {'q', 'u', 'i', 't', '\0'};

        static const struct iovec iov[] = {
            {
                .iov_base = (void*)iov0,
                .iov_len = sizeof(iov0),
            },
        };
        static const size_t iovlen = sizeof(iov) / sizeof(iov[0]);
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));

        msg.msg_iov = (struct iovec*)iov;
        msg.msg_iovlen = (typeof(msg.msg_iovlen))iovlen;

        ssize_t m = sendmsg(sd, &msg, 0);

        if (m != sizeof(iov0))
            OE_TEST("sendmsg() failed: quit" == NULL);
    }

    close(sd);
}
#endif
