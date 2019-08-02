// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESS_MANAGER_H_
#define _OE_SWITCHLESS_MANAGER_H_

#include "hostthread.h"
#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/edger8r/switchless.h>

OE_EXTERNC_BEGIN

typedef struct _oe_switchless_manager
{
    oe_switchless_t switchless;
    oe_thread enclave_worker;
    oe_thread host_worker;
} oe_switchless_manager_t;

void oe_switchless_manager_init(oe_enclave_t* enclave);

oe_result_t oe_switchless_manager_startup(oe_enclave_t* enclave);

void oe_switchless_manager_shutdown(oe_enclave_t* enclave);

OE_EXTERNC_END

#endif /* _OE_SWITCHLESS_MANAGER_H_ */
