// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _EDGER8R_PROLOGUE_H
#define _EDGER8R_PROLOGUE_H

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <netdb.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/posix/epoll.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#define oe_call_enclave_function oe_call_internal_enclave_function

#endif /* _EDGER8R_PROLOGUE_H */
