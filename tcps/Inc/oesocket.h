/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

typedef enum oe_socket_error_t {
    OE_WSA_NOT_ENOUGH_MEMORY = 8,
    OE_WSAEACCES          = 10013,
    OE_WSAEFAULT          = 10014,
    OE_WSAEINVAL          = 10022,
    OE_WSAEMFILE          = 10024,
    OE_WSAEWOULDBLOCK     = 10035,
    OE_WSAEINPROGRESS     = 10036,
    OE_WSAENOPROTOOPT     = 10042,
    OE_WSAEPROTONOSUPPORT = 10043,
    OE_WSAEAFNOSUPPORT    = 10047,
    OE_WSAENETDOWN        = 10050,
    OE_WSAECONNABORTED    = 10053,
    OE_WSAECONNRESET      = 10054,
    OE_WSAENOBUFS         = 10055,
    OE_WSASYSNOTREADY     = 10091,
    OE_WSANO_RECOVERY     = 11003
} oe_socket_error_t;

typedef enum oe_socket_address_family_t {
    OE_AF_INET = 2,
    OE_AF_INET6 = 23,
} oe_socket_address_family_t;

typedef enum oe_socket_type_t {
    OE_SOCK_STREAM = 1,
} oe_socket_type_t;

typedef enum oe_shutdown_how_t {
    OE_SD_RECEIVE = 0,
    OE_SD_SEND = 1,
    OE_SD_BOTH = 2,
} oe_shutdown_how_t;
