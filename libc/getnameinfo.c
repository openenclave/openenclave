// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/netdb.h>

struct sockaddr;

int getnameinfo(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    return oe_getnameinfo(
        (const struct oe_sockaddr*)sa,
        salen,
        host,
        hostlen,
        serv,
        servlen,
        flags);
}
