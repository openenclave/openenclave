// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

struct __OE_ADDRINFO
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    oe_socklen_t ai_addrlen;
    struct __OE_SOCKADDR* ai_addr;
    char* ai_canonname;
    struct __OE_ADDRINFO* ai_next;
};
