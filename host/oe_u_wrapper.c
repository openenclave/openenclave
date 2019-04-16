// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <netdb.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/epoll.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#define oe_call_enclave_function oe_call_internal_enclave_function

#include "oe_u.c"

const oe_ocall_func_t* oe_get_internal_ocall_function_table(void)
{
    return __oe_ocall_function_table;
}

size_t oe_get_internal_ocall_function_table_size(void)
{
    return OE_COUNTOF(__oe_ocall_function_table);
}
