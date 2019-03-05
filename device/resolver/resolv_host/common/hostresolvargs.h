// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOSTRESOLVARGS_H
#define _OE_HOSTRESOLVARGS_H

#include <openenclave/internal/device.h>

OE_EXTERNC_BEGIN

typedef enum _oe_hostresolv_op
{
    OE_HOSTRESOLV_OP_NONE,
    // get addrinfo size must be immediately followed by get addr info. Get addr
    // info copies and calls freeaddrinfo on the host side. There needs to be a
    // lock on thses things
    OE_HOSTRESOLV_OP_GETADDRINFO,
    OE_HOSTRESOLV_OP_GETNAMEINFO,
    OE_HOSTRESOLV_OP_SHUTDOWN
} oe_hostresolv_op_t;

typedef struct _oe_hostresolv_args
{
    oe_hostresolv_op_t op;
    int err;
    union {
        struct
        {
            int64_t ret;
            int32_t hint_flags;    //  (AI_V4MAPPED | AI_ADDRCONFIG) means none
            int32_t hint_family;   //  AF_UNSPEC means none
            int32_t hint_socktype; //  none = 0
            int32_t hint_protocol; //  none = 0
            int32_t buffer_len;
            int32_t nodelen;
            int32_t servicelen;
            // results in buf
        } getaddrinfo;
        struct
        {
            int64_t ret;
            int32_t addrlen; // in
            // struct oe_sockaddr *addr;  data in buf
            int32_t hostlen;
            // Hostname returned in buf
            int32_t servlen;
            // Service name returned in buf+hostlen after hostname
            int32_t flags;
        } getnameinfo;
        struct
        {
            int64_t ret;
        } shutdown_device;
    } u;
    uint8_t buf[];
} oe_hostresolv_args_t;

OE_EXTERNC_END

#endif /* _OE_HOST_RESOLVARGS_H */
