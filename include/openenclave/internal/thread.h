// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_THREAD_H
#define _OE_INCLUDE_THREAD_H

/*
**==============================================================================
**
** oe_thread_wake_wait_args_t
**
**==============================================================================
*/

typedef struct _oe_thread_wake_wait_args
{
    const void* waiter_tcs;
    const void* self_tcs;
} oe_thread_wake_wait_args_t;

#endif //_OE_INCLUDE_THREAD_H

