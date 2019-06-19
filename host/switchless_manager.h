// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESS_MANAGER_H_
#define _OE_SWITCHLESS_MANAGER_H_

#include <openenclave/bits/defs.h>
#include <openenclave/bits/lockless_queue.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdint.h>
#include <openenclave/edger8r/switchless.h>

#if _MSC_VER
#include <Windows.h>
#elif defined __GNUC__
#include <pthread.h>
#endif /* _MSC_VER or __GNUC__ */

OE_EXTERNC_BEGIN

#if _MSC_VER
typedef HANDLE oe_thread_t;
#elif defined __GNUC__
typedef pthread_t oe_thread_t;
#endif /* _MSC_VER or __GNUC__ */

typedef struct _oe_switchless_manager
{
    oe_switchless_t switchless;
    oe_thread_t enclave_worker;
} oe_switchless_manager_t;

void oe_switchless_manager_init(oe_enclave_t* enclave);

oe_result_t oe_switchless_manager_startup(oe_enclave_t* enclave);

void oe_switchless_manager_shutdown(oe_enclave_t* enclave);

OE_EXTERNC_END

#endif /* _OE_SWITCHLESS_MANAGER_H_ */
