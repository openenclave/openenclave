/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <openenclave/internal/time.h>

#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/host_resolver.h>

#include <resolver_test_t.h>
#include <stdio.h>
#include <string.h>

size_t oe_debug_malloc_check();

struct addrinfo;

int ecall_device_init()
{
    oe_resolver_t* host_resolver = oe_get_hostresolver();
    (void)oe_register_resolver(2, host_resolver);
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
        .sin_family = OE_AF_HOST,
        .sin_port = 22,
        .sin_addr.s_addr = oe_htonl(OE_INADDR_LOOPBACK)};

    int rslt = oe_getnameinfo(
        (const struct oe_sockaddr*)&addr,
        sizeof(addr),
        host,
        sizeof(host),
        serv,
        sizeof(serv),
        0);

    if (rslt != 0)
    {
        printf("getnameinfo failed\n");
        return OE_FAILURE;
    }
    else
    {
        memcpy(buffer, host, strnlen(host, 255));
        printf("getnameinfo passed\n");
        return OE_OK; // status;
    }
}

int ecall_getaddrinfo(struct addrinfo** buffer)

{
    struct oe_addrinfo* ai = NULL;
    int status = OE_FAILURE;

    const char host[] = {"localhost"};
    const char service[] = {"telnet"};

    int rslt = oe_getaddrinfo(host, service, NULL, (struct oe_addrinfo**)&ai);

    if (rslt == 0)
    {
        struct oe_addrinfo* thisinfo = ai;
        size_t buffer_required = (size_t)0;

        // Allocate host memory and copy the chain of addrinfos

        do
        {
            buffer_required += sizeof(struct oe_addrinfo);
            if (thisinfo->ai_addr)
            {
                buffer_required += sizeof(struct oe_sockaddr);
            }
            if (thisinfo->ai_canonname)
            {
                buffer_required += strlen(thisinfo->ai_canonname) + 1;
            }

            thisinfo = thisinfo->ai_next;

        } while (thisinfo != NULL);

        {
            size_t canon_namelen = 0;
            uint8_t* bufptr = oe_host_calloc(0, buffer_required);
            struct oe_addrinfo* retinfo = (struct oe_addrinfo*)bufptr;
            thisinfo = ai;
            do
            {
                // Set up the pointers in the destination structure to point
                // at the buffer after the addrinfo structure.
                struct oe_addrinfo* buf_info = (struct oe_addrinfo*)bufptr;
                buf_info->ai_flags = thisinfo->ai_flags;
                buf_info->ai_family = thisinfo->ai_family;
                buf_info->ai_socktype = thisinfo->ai_socktype;
                buf_info->ai_protocol = thisinfo->ai_protocol;
                buf_info->ai_addrlen = thisinfo->ai_addrlen;
                buf_info->ai_canonname = NULL;
                buf_info->ai_addr = NULL;
                buf_info->ai_next = NULL;

                bufptr += sizeof(struct oe_addrinfo);
                if (thisinfo->ai_addr)
                {
                    buf_info->ai_addr = (struct oe_sockaddr*)(bufptr);
                    memcpy(
                        buf_info->ai_addr,
                        thisinfo->ai_addr,
                        buf_info->ai_addrlen);
                    bufptr += buf_info->ai_addrlen;
                }
                if (thisinfo->ai_canonname)
                {
                    canon_namelen = strlen(thisinfo->ai_canonname) + 1;
                    buf_info->ai_canonname = (char*)bufptr;
                    memcpy(
                        buf_info->ai_canonname,
                        thisinfo->ai_canonname,
                        canon_namelen);
                    bufptr += canon_namelen;
                }

                thisinfo = thisinfo->ai_next;
                if (thisinfo)
                {
                    buf_info->ai_next = (struct oe_addrinfo*)bufptr;
                }

            } while (thisinfo != NULL);

            printf(
                "bufptr(end)-bufptr(start) = %ld\n",
                bufptr - (uint8_t*)retinfo);
            *buffer = (struct addrinfo*)retinfo;

            oe_freeaddrinfo(ai);
        }
    }

    printf("getaddrinfo rslt = %d\n", rslt);
    return status;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    256,  /* StackPageCount */
    1);   /* TCSCount */
