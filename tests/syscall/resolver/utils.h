// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TEST_RESOLVER_UTILS_H
#define _TEST_RESOLVER_UTILS_H

#if defined(_MSC_VER)
#include <winsock2.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif
#include <string.h>
#include <sys/types.h>

OE_INLINE int addrinfo_compare(struct addrinfo* p, struct addrinfo* q)
{
    if (!p || !q)
        return -1;

    for (; p && q; p = p->ai_next, q = q->ai_next)
    {
        if (p->ai_flags != q->ai_flags)
            return -2;

        if (p->ai_family != q->ai_family)
            return -3;

        if (p->ai_socktype != q->ai_socktype)
            return -4;

        if (p->ai_protocol != q->ai_protocol)
            return -5;

        if (p->ai_addrlen != q->ai_addrlen)
            return -6;

        if (p->ai_addr && !q->ai_addr)
            return -7;

        if (!p->ai_addr && q->ai_addr)
            return -8;

        if (p->ai_addr && q->ai_addr)
        {
            if (memcmp(p->ai_addr, q->ai_addr, p->ai_addrlen) != 0)
                return -9;
        }

        if (p->ai_canonname && !q->ai_canonname)
            return -10;

        if (!p->ai_canonname && q->ai_canonname)
            return -11;

        if (p->ai_canonname && q->ai_canonname)
        {
            if (strcmp(p->ai_canonname, q->ai_canonname) != 0)
                return -12;
        }
    }

    if (p || q)
        return -13;

    return 0;
}

OE_INLINE void addrinfo_dump(struct oe_addrinfo* ai)
{
    printf("=== dump_addrinfo()\n");

    for (struct oe_addrinfo* p = ai; p; p = p->ai_next)
    {
        printf("ai_flags=%d\n", p->ai_flags);
        printf("ai_family=%d\n", p->ai_family);
        printf("ai_socktype=%d\n", p->ai_socktype);
        printf("ai_protocol=%d\n", p->ai_protocol);
        printf("ai_addrlen=%d\n", p->ai_addrlen);

        if (p->ai_addr)
        {
            const unsigned char* s = (const unsigned char*)p->ai_addr;

            printf("ai_addr=");

            for (size_t i = 0; i < p->ai_addrlen; i++)
                printf("%02x ", s[i]);

            printf("\n");
        }
        else
        {
            printf("ai_addr=null\n");
        }

        printf("ai_canonname=%p\n", p->ai_canonname);
        printf("ai_next=%p\n", p->ai_next);
        printf("===\n");
    }

    printf("\n");
}

#endif /* _TEST_RESOLVER_UTILS_H */
