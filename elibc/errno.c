// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/sgxtypes.h>

int* __elibc_errno_location(void)
{
    td_t* td = (td_t*)oe_get_thread_data();
    return &td->linux_errno;
}
