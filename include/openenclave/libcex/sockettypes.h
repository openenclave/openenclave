/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

typedef enum oe_socket_error_t
{
#ifdef LINUX
    OE_ENOMEM = 8,
    OE_EACCES = 13,
    OE_EFAULT = 14,
    OE_EINVAL = 22,
    OE_EMFILE = 24,
    OE_EAGAIN = 11,
    OE_EINPROGRESS = 115,
    OE_ENOPROTOOPT = 92,
    OE_EPROTONOSUPPORT = 93,
    OE_EAFNOSUPPORT = 97,
    OE_ENETDOWN = 100,
    OE_ECONNABORTED = 103,
    OE_ECONNRESET = 104,
    OE_ENOBUFS = 105,
    OE_SYSNOTREADY = OE_EFAULT, // WSA-only
    OE_ENOTRECOVERABLE = 131
#else
    OE_ENOMEM = 8,
    OE_EACCES = 10013,
    OE_EFAULT = 10014,
    OE_EINVAL = 10022,
    OE_EMFILE = 10024,
    OE_EAGAIN = 10035, // = WSAEWOULDBLOCK
    OE_EINPROGRESS = 10036,
    OE_ENOPROTOOPT = 10042,
    OE_EPROTONOSUPPORT = 10043,
    OE_EAFNOSUPPORT = 10047,
    OE_ENETDOWN = 10050,
    OE_ECONNABORTED = 10053,
    OE_ECONNRESET = 10054,
    OE_ENOBUFS = 10055,
    OE_SYSNOTREADY = 10091,
    OE_ENOTRECOVERABLE = 11003
#endif
} oe_socket_error_t;

typedef enum oe_socket_address_family_t
{
    OE_AF_INET = 2,
#ifdef LINUX
    OE_AF_INET6 = 10,
#else
    OE_AF_INET6 = 23,
#endif
} oe_socket_address_family_t;

typedef enum oe_socket_type_t
{
    OE_SOCK_STREAM = 1,
} oe_socket_type_t;

typedef enum oe_shutdown_how_t
{
    OE_SHUT_RD = 0,   // WSA = OE_SD_RECEIVE
    OE_SHUT_WR = 1,   // WSA = OE_SHUT_WR
    OE_SHUT_RDWR = 2, // WSA = OE_SHUT_RDWR
} oe_shutdown_how_t;
