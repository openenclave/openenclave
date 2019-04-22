// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _EDGER8R_PROLOGUE_H
#define _EDGER8R_PROLOGUE_H

#define OE_NEED_STDC_NAMES

#include <openenclave/internal/calls.h>

#define __oe_ecalls_table_size __oe_internal_ecalls_table_size
#define __oe_ecalls_table __oe_internal_ecalls_table
#define oe_call_host_function oe_call_internal_host_function

#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/sys/utsname.h>
#include <openenclave/internal/posix/epoll.h>

#endif /* _EDGER8R_PROLOGUE_H */
