// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define OE_LIBC_SUPPRESS_DEPRECATIONS
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#if defined(_MSC_VER)
#define OE_NEED_STD_NAMES
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
static void sleep(int secs)
{
    Sleep(secs * 1000);
}
typedef HANDLE pthread_t;
#else
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include "resolver_test_u.h"
#include "../utils.h"

#define SERVER_PORT "12345"

static void _free_addrinfo(struct oe_addrinfo* res)
{
    struct oe_addrinfo* p;

    for (p = res; p;)
    {
        struct oe_addrinfo* next = p->ai_next;

        free(p->ai_addr);
        free(p->ai_canonname);
        free(p);

        p = next;
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* client_enclave = NULL;
    int ret = 0;
    const uint32_t flags = oe_get_create_flags();

    char host[256];

    struct oe_addrinfo* addrinfo = NULL;
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    result = oe_create_resolver_test_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &client_enclave);

    OE_TEST(result == OE_OK);

    OE_TEST(ecall_device_init(client_enclave, &ret) == OE_OK);

    OE_TEST(ecall_getaddrinfo(client_enclave, &ret, &addrinfo) == OE_OK);

    addrinfo_dump(addrinfo);

    if (!addrinfo)
    {
        printf("host received: addrinfo == NULL\n");
    }
    else
    {
        struct oe_addrinfo* thisinfo = addrinfo;
        bool found = false;

        while (thisinfo)
        {
            char node[NI_MAXHOST];
            char port[NI_MAXSERV];
            int err = getnameinfo(
                (const struct sockaddr*)thisinfo->ai_addr,
                (socklen_t)thisinfo->ai_addrlen,
                node,
                sizeof(node),
                port,
                sizeof(port),
                NI_NUMERICHOST | NI_NUMERICSERV);
            if (err == 0)
            {
                printf(
                    "host received: addrinfo->ai_addr: %s port %s\n",
                    node,
                    port);

                if ((strcmp(node, "127.0.0.1") == 0) ||
                    (strcmp(node, "::1") == 0))
                {
                    found = true;
                }
            }

            thisinfo = thisinfo->ai_next;
        }

        _free_addrinfo(addrinfo);

        OE_TEST(found);
    }

    OE_TEST(
        ecall_getnameinfo(client_enclave, &ret, host, sizeof(host)) == OE_OK);

    {
        OE_TEST(strlen(host) > 0); // Can't be sure what the host result will
                                   // be. Windows returns the node name
        printf("host received: host = %s\n", host);
    }

    OE_TEST(oe_terminate_enclave(client_enclave) == OE_OK);

    printf("=== passed all tests (resolver_test)\n");

    return 0;
}
