// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_STRUCT_ADDRINFO
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct __OE_STRUCT_SOCKADDR* ai_addr;
    char* ai_canonname;
    struct __OE_STRUCT_ADDRINFO* ai_next;
};
