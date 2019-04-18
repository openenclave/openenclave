// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <openenclave/internal/calls.h>

#define __oe_ecalls_table_size __oe_internal_ecalls_table_size
#define __oe_ecalls_table __oe_internal_ecalls_table
#define oe_call_host_function oe_call_internal_host_function
//#define epoll_event oe_epoll_event
#define pollfd oe_pollfd

#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/internal/epoll.h>

#include "oe_t.c"
