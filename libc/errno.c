// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/sgxtypes.h>
#include <pthread.h>

int* __errno_location()
{
    TD* td = (TD*)oe_get_thread_data();
    assert(td);
    return &td->linux_errno;
}
