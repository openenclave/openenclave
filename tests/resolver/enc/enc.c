/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/resolver.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/typeinfo.h>

#include <resolver_test_t.h>
#include <stdio.h>
#include <string.h>
#include "../utils.h"

size_t oe_debug_malloc_check();

struct addrinfo;

int ecall_device_init()
{
    OE_TEST(oe_load_module_hostfs() == OE_OK);
    OE_TEST(oe_load_module_hostsock() == OE_OK);
    OE_TEST(oe_load_module_polling() == OE_OK);
    OE_TEST(oe_load_module_eventfd() == OE_OK);
    OE_TEST(oe_load_module_hostresolver() == OE_OK);
    return 0;
}

int ecall_getnameinfo(char* buffer, size_t bufflen)
{
    int status = OE_FAILURE;
    (void)buffer;
    (void)bufflen;
    (void)status;

    char host[256] = {0};
    char serv[256] = {0};

    struct oe_sockaddr_in addr = {
        .sin_family = OE_AF_INET,
        .sin_port = 22,
        .sin_addr.s_addr = oe_htonl(OE_INADDR_LOOPBACK)};

    printf("s_addr=%x\n", addr.sin_addr.s_addr);

    int rslt = oe_getnameinfo(
        (const struct oe_sockaddr*)&addr,
        sizeof(addr),
        host,
        sizeof(host),
        serv,
        sizeof(serv),
        0);

    OE_TEST(rslt == 0);
    OE_TEST(strcmp(host, "") != 0);
    OE_TEST(strcmp(serv, "") != 0);

    strlcpy(buffer, host, bufflen);

    return 0;
}

extern oe_struct_type_info_t __oe_addrinfo_sti;

int ecall_getaddrinfo(struct addrinfo** buffer)
{
    struct oe_addrinfo* ai = NULL;
    struct addrinfo* ai2 = NULL;
    size_t size = 0;
    oe_struct_type_info_t* structure = &__oe_addrinfo_sti;

    const char host[] = {"localhost"};
    const char serv[] = {"telnet"};

    OE_TEST(oe_getaddrinfo(host, serv, NULL, (struct oe_addrinfo**)&ai) == 0);
    OE_TEST(getaddrinfo(host, serv, NULL, &ai2) == 0);
    OE_TEST(addrinfo_compare((struct addrinfo*)ai, ai2) == 0);

    /* Determine the size of the host output buffer. */
    OE_TEST(
        oe_type_info_clone(structure, ai, NULL, &size) == OE_BUFFER_TOO_SMALL);

    /* Allocate host memory and initialize the flat allocator. */
    OE_TEST((*buffer = oe_host_calloc(1, size)));

    /* Copy the result from enclave to host memory. */

    OE_TEST(oe_type_info_clone(structure, ai, *buffer, &size) == OE_OK);

    addrinfo_dump((struct addrinfo*)ai);
    addrinfo_dump(*buffer);

    OE_TEST(addrinfo_compare((struct addrinfo*)ai, *buffer) == 0);

    oe_freeaddrinfo(ai);
    freeaddrinfo(ai2);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    1);   /* TCSCount */
